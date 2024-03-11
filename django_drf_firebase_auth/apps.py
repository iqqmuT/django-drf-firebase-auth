from django.apps import AppConfig
from firebase_admin import initialize_app

class FirebaseAuthConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'django_drf_firebase_auth'
    label = 'drffirebaseauth'

    def ready(self):
        initialize_app()
