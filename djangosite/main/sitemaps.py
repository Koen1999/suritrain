from datetime import date

from django.apps import apps
from django.contrib.sitemaps import Sitemap

app_config = apps.get_app_config("main")


class StaticViewSitemap(Sitemap):
    priority = 1
    changefreq = "weekly"
    protocol = "https"

    mapping = {"index": ""}

    def items(self) -> list[str]:
        return list(self.mapping.keys())

    def location(self, obj) -> str:  # noqa: ANN001
        return self.mapping[obj]

    def lastmod(self, item) -> date:  # noqa: ANN001, ARG002
        return app_config.startup_date
