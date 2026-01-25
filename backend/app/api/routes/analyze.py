"""
Endpoint /analyze para analizar URLs

Rate Limit: 30 requests/minuto por IP
"""

import logging
from datetime import datetime

from fastapi import APIRouter, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings

# Rate limiter para este endpoint
limiter = Limiter(key_func=get_remote_address)
from app.core.security import validate_and_normalize_url
from app.schemas.analyze import (
    AnalyzeRequest,
    AnalyzeResponse,
    CrawlResult,
    CrawlStatus,
    Timestamps,
    ConnectionMode,
    ModelType,
    ApisConsulted
)
from app.services.predictor import predictor
from app.services.heuristic_predictor import heuristic_predictor
from app.services.tranco_service import tranco_service
from app.services.virustotal_service import virustotal_service
from app.services.crawler_service import crawler_service
from app.schemas.analyze import Signal, Severity

logger = logging.getLogger(__name__)
router = APIRouter()


def determine_mode(requested_mode: ConnectionMode) -> tuple[ConnectionMode, bool, bool]:
    """
    Determina el modo efectivo y qué APIs usar.

    Returns:
        (mode_used, use_tranco, use_virustotal)
    """
    if requested_mode == ConnectionMode.OFFLINE:
        return ConnectionMode.OFFLINE, False, False

    if requested_mode == ConnectionMode.ONLINE:
        return ConnectionMode.ONLINE, True, True

    # Modo AUTO: verificar disponibilidad de APIs
    tranco_available = tranco_service.enabled
    vt_available = virustotal_service.enabled

    if tranco_available or vt_available:
        return ConnectionMode.ONLINE, tranco_available, vt_available
    else:
        return ConnectionMode.OFFLINE, False, False


@router.post("/analyze", response_model=AnalyzeResponse, tags=["Analysis"])
@limiter.limit("30/minute")
async def analyze_url(request: Request, data: AnalyzeRequest):
    """
    Analiza una URL y devuelve score de riesgo con señales explicables.

    - **url**: URL a analizar (requerido)
    - **mode**: Modo de conexion (auto/online/offline)
    - **options**: Opciones de analisis (opcional)

    Returns:
        Score 0-100, nivel de riesgo, señales detectadas y recomendaciones
    """
    start_time = datetime.now()

    # Validar y normalizar URL (proteccion SSRF)
    normalized_url, error = validate_and_normalize_url(data.url)
    if error:
        raise HTTPException(status_code=400, detail=f"URL invalida: {error}")

    try:
        # Determinar modo efectivo
        mode_used, use_tranco, use_virustotal = determine_mode(data.mode)
        model_used = data.model

        logger.info(f"Analizando URL con modelo {model_used.value}, modo {mode_used.value}: tranco={use_tranco}, vt={use_virustotal}")

        # Seleccionar el modelo correcto
        if model_used == ModelType.ML:
            # Modelo ML (GradientBoosting)
            score, probability, risk_level, signals = predictor.predict(
                data.url,
                use_tranco=use_tranco,
                use_virustotal=use_virustotal
            )
            recommendations = predictor.get_recommendations(risk_level, signals)
        else:
            # Modelo Heuristico (reglas con pesos calibrados)
            score, probability, risk_level, signals = heuristic_predictor.predict(
                data.url,
                use_tranco=use_tranco,
                use_virustotal=use_virustotal
            )
            recommendations = heuristic_predictor.get_recommendations(risk_level, signals)

        # Determinar qué APIs fueron efectivamente consultadas
        apis_consulted = ApisConsulted(
            tranco=use_tranco and tranco_service.enabled,
            virustotal=any(s.id.startswith("VIRUSTOTAL") for s in signals),
            database=False  # TODO: implementar cuando BD esté activa
        )

        # Crawl result
        enable_crawler = data.options.enable_crawler if data.options else False
        crawl_result = CrawlResult(
            enabled=enable_crawler,
            status=CrawlStatus.SKIPPED
        )

        # Ejecutar crawler headless si está habilitado
        if enable_crawler and crawler_service.is_available:
            try:
                timeout = data.options.timeout_seconds if data.options else 20
                max_redirects = data.options.max_redirects if data.options else 5

                import asyncio
                crawl_data = await crawler_service.crawl_url(
                    normalized_url,
                    timeout_seconds=timeout,
                    max_redirects=max_redirects,
                    take_screenshot=False
                )

                # Actualizar crawl_result
                if crawl_data.success:
                    crawl_result = CrawlResult(
                        enabled=True,
                        status=CrawlStatus.OK,
                        final_url=crawl_data.final_url,
                        redirect_chain=crawl_data.redirect_chain,
                        html_fingerprint=crawl_data.evidence.html_hash,
                        evidence={
                            'has_login_form': crawl_data.evidence.has_login_form,
                            'has_password_field': crawl_data.evidence.has_password_field,
                            'has_credit_card_field': crawl_data.evidence.has_credit_card_field,
                            'page_title': crawl_data.evidence.page_title,
                            'brands_detected': crawl_data.evidence.brand_logos_detected,
                            'phishing_patterns': len(crawl_data.evidence.suspicious_text_patterns),
                            'external_form': crawl_data.evidence.external_form_submission,
                        }
                    )

                    # Generar señales del crawl y agregarlas
                    # Solo si el sitio NO está en Tranco (evitar falsos positivos en sitios legítimos)
                    is_in_tranco = any(s.id == "DOMAIN_IN_TRANCO" for s in signals)

                    crawl_signals = crawler_service.generate_signals_from_crawl(
                        crawl_data, normalized_url
                    )

                    # Filtrar señales del crawl si el sitio está en Tranco
                    if is_in_tranco:
                        # Solo mantener señales críticas para sitios de Tranco
                        critical_signals = ['SSL_CERTIFICATE_ERROR', 'FORM_SUBMITS_EXTERNALLY', 'REDIRECT_TO_DIFFERENT_DOMAIN']
                        crawl_signals = [s for s in crawl_signals if s['id'] in critical_signals]

                    # Convertir señales del crawl al formato Signal y agregar al score
                    for sig_data in crawl_signals:
                        signal = Signal(
                            id=sig_data['id'],
                            severity=Severity(sig_data['severity']),
                            weight=sig_data['weight'],
                            evidence=sig_data['evidence'],
                            explanation=sig_data['explanation']
                        )
                        signals.append(signal)
                        score = min(100, score + sig_data['weight'])

                    # Recalcular nivel de riesgo
                    if score == 0:
                        risk_level = risk_level  # Mantener
                    elif score <= 30:
                        from app.schemas.analyze import RiskLevel
                        risk_level = RiskLevel.LOW
                    elif score <= 70:
                        from app.schemas.analyze import RiskLevel
                        risk_level = RiskLevel.MEDIUM
                    else:
                        from app.schemas.analyze import RiskLevel
                        risk_level = RiskLevel.HIGH

                else:
                    crawl_result = CrawlResult(
                        enabled=True,
                        status=CrawlStatus.ERROR if crawl_data.error_message else CrawlStatus.TIMEOUT,
                        final_url=crawl_data.final_url,
                        redirect_chain=crawl_data.redirect_chain,
                        evidence={'error': crawl_data.error_message}
                    )

                logger.info(f"Crawl completado: {crawl_data.success}, duration={crawl_data.duration_ms}ms")

            except Exception as e:
                logger.error(f"Error en crawler: {e}")
                crawl_result = CrawlResult(
                    enabled=True,
                    status=CrawlStatus.ERROR,
                    evidence={'error': str(e)}
                )

        end_time = datetime.now()
        duration_ms = int((end_time - start_time).total_seconds() * 1000)

        return AnalyzeResponse(
            url=data.url,
            normalized_url=normalized_url,
            score=score,
            risk_level=risk_level,
            model_used=model_used,
            mode_used=mode_used,
            apis_consulted=apis_consulted,
            signals=signals,
            recommendations=recommendations,
            crawl=crawl_result,
            timestamps=Timestamps(
                requested_at=start_time,
                completed_at=end_time,
                duration_ms=duration_ms
            )
        )

    except Exception as e:
        logger.error(f"Error analizando URL {request.url}: {e}")
        raise HTTPException(status_code=500, detail="Error interno al analizar URL")
