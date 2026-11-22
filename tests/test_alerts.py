from datetime import date

from app import alerts
from app.business_days import SpainCalendar

cal = SpainCalendar()  # solo festivos nacionales


def test_festivos_nacionales_y_fines_de_semana():
    assert cal.is_holiday(date(2026, 12, 8))  # Inmaculada Concepción
    assert cal.is_holiday(date(2026, 12, 25))  # Navidad
    assert not cal.is_business_day(date(2026, 12, 5))  # sábado
    assert cal.is_business_day(date(2026, 12, 4))  # viernes


def test_dia_habil_anterior_salta_fin_de_semana_y_festivo():
    # 27.12 domingo -> 26 sábado -> 25 Navidad -> 24 jueves
    assert cal.previous_business_day(date(2026, 12, 27)) == date(2026, 12, 24)


def test_ejemplo_juan_perez_aviso_el_dia_anterior():
    due = date(2026, 12, 5)
    assert alerts.deadline_alert(1, due, [1], date(2026, 12, 3), cal) is None
    a = alerts.deadline_alert(1, due, [1], date(2026, 12, 4), cal)
    assert a.kind == alerts.AVISO and a.target_date == date(2026, 12, 4) and a.days_left == 1


def test_aviso_que_cae_en_fin_de_semana_se_adelanta():
    # Plazo lunes 30.11.2026, aviso 1 día antes = domingo -> se adelanta al viernes 27.11
    due = date(2026, 11, 30)
    assert alerts.alert_date_for(due, 1, cal) == date(2026, 11, 27)
    assert alerts.deadline_alert(1, due, [1], date(2026, 11, 27), cal).kind == alerts.AVISO


def test_varios_avisos_usan_la_fecha_mas_reciente_alcanzada():
    due = date(2026, 12, 18)  # viernes
    a7 = alerts.deadline_alert(1, due, [7, 3, 1], date(2026, 12, 11), cal)
    assert a7.target_date == date(2026, 12, 11)
    a3 = alerts.deadline_alert(1, due, [7, 3, 1], date(2026, 12, 15), cal)
    assert a3.target_date == date(2026, 12, 15)
    # entre avisos se mantiene la última fecha alcanzada (idempotencia evita reenvío)
    assert alerts.deadline_alert(1, due, [7, 3, 1], date(2026, 12, 16), cal).target_date == date(2026, 12, 15)


def test_vence_hoy_y_vencido():
    due = date(2026, 12, 4)
    assert alerts.deadline_alert(1, due, [1], due, cal).kind == alerts.VENCE_HOY
    v = alerts.deadline_alert(1, due, [1], date(2026, 12, 7), cal)
    assert v.kind == alerts.VENCIDO and v.days_left == -3
    # en fin de semana no se insiste con vencidos
    assert alerts.deadline_alert(1, due, [1], date(2026, 12, 6), cal) is None


def test_solicitud_documento_periodicidad():
    assert alerts.document_request_due(None, 3, date(2026, 12, 1))
    assert not alerts.document_request_due(date(2026, 12, 1), 3, date(2026, 12, 3))
    assert alerts.document_request_due(date(2026, 12, 1), 3, date(2026, 12, 4))
