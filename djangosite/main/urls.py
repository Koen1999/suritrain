from django.contrib.auth import views as auth_views
from django.contrib.sitemaps.views import sitemap
from django.urls import path

from . import sitemaps, views

app_name = "main"


urlpatterns = [
    path("", views.index, name="index"),
    # path("register", views.register, name="register"),
    path(
        "login",
        auth_views.LoginView.as_view(template_name="main/login.html"),
        name="login",
    ),
    path(
        "logout",
        auth_views.LogoutView.as_view(template_name="main/index.html"),
        name="logout",
    ),
    path("leaderboard", views.leaderboard, name="leaderboard"),
    path("scenarios", views.scenarios, name="scenarios"),
    path("scenario/first", views.scenario_first, name="scenario_first"),
    path("scenario/<int:scenario_id>", views.scenario, name="scenario"),
    path(
        "scenario/<int:scenario_id>/test/<int:test_id>",
        views.scenario_test,
        name="scenario_test",
    ),
    path("check", views.check, name="check"),
    path("submit/<int:scenario_id>", views.submit, name="submit"),
    path("status/<int:scenario_id>", views.status, name="status"),
    path("handout", views.handout, name="handout"),
]

urlpatterns += [
    path(
        "sitemap.xml",
        sitemap,
        {
            "sitemaps": {
                "static": sitemaps.StaticViewSitemap(),
            }
        },
        name="django.contrib.sitemaps.views.sitemap",
    ),
]
