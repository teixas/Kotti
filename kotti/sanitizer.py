from bleach import clean

from kotti import get_settings


def sanitize(event):
    settings = get_settings()
    if settings.get('kotti.sanitizer', False):
        fields = settings.get('kotti.sanitizer.fields', []).split()
        for field in fields:
            content_type, content_field = field.split('.')
            context = event.object
            if context.type == content_type:
                setattr(context, content_field,
                        clean(getattr(context, content_field)))
