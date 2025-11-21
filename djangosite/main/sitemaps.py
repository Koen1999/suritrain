from django.contrib.sitemaps import Sitemap
from django.apps import apps

app_config = apps.get_app_config("main")


class StaticViewSitemap(Sitemap):
    priority = 1
    changefreq = "weekly"
    protocol = "https"

    mapping = {"index": ""}

    def items(self):
        return list(self.mapping.keys())

    def location(self, item):
        return self.mapping[item]

    def lastmod(self, item):
        return app_config.startup_date
