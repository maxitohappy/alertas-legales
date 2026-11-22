"""Calendario de días hábiles en España (fines de semana + festivos nacionales y autonómicos)."""

from datetime import date, timedelta

import holidays


class SpainCalendar:
    def __init__(self, subdiv: str | None = None):
        self._holidays = holidays.country_holidays("ES", subdiv=subdiv)

    def is_holiday(self, d: date) -> bool:
        return d in self._holidays

    def holiday_name(self, d: date) -> str | None:
        return self._holidays.get(d)

    def is_business_day(self, d: date) -> bool:
        return d.weekday() < 5 and d not in self._holidays

    def previous_business_day(self, d: date) -> date:
        """Devuelve d si es hábil; si no, el día hábil inmediatamente anterior."""
        while not self.is_business_day(d):
            d -= timedelta(days=1)
        return d
