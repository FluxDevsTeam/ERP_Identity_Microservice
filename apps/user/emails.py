import os
from django.conf import settings
from django.core.mail import send_mail
from django.template import Template, Context
from datetime import datetime

from django.utils.functional import SimpleLazyObject


organization = SimpleLazyObject(lambda: {
    'support_phone_number': getattr('phone_number', None),
    'support_email': getattr('customer_support_email', None),
    'brand_logo': getattr('brand_logo', None),
    'facebook': getattr('facebook', None),
    'instagram': getattr('instagram', None),
    'x': getattr('twitter', None),
    'linkedin': getattr('linkedin', None),
    'tiktok': getattr('tiktok', None),
})


def get_support_phone_number():
    return organization['support_phone_number']


def get_support_email():
    return organization['support_email']


def get_brand_logo():
    return organization['brand_logo']


def get_fb_link():
    return organization['facebook']


def get_ig_link():
    return organization['instagram']


def get_x_link():
    return organization['x']


def get_linkedin_link():
    return organization['linkedin']


def get_tiktok_link():
    return organization['tiktok']


developer = SimpleLazyObject(lambda: {
    'brand_name': getattr('brand_name', None),
    'terms_of_service': getattr('terms_of_service', None)
})


def get_brand_name():
    return developer['brand_name']


def get_terms_of_service():
    return developer['terms_of_service']


def send_generic_email(user_email, email_type, subject, action, message, otp=None, link=None, link_text=None):
    try:
        valid_email_types = [
            'otp', 'confirmation', 'reset_link'
        ]
        if email_type not in valid_email_types:
            raise ValueError(f"Invalid email_type: must be one of {valid_email_types}")

        context = {
            'subject': subject,
            'action': action,
            'message': message,
            'otp': otp,
            'link': link,
            'link_text': link_text,
            'site_url': settings.SITE_URL,
            'current_year': datetime.now().year,

            'support_email': get_support_email(),
            'support_phone_number': get_support_phone_number(),
            'brand_name': get_brand_name(),
            'brand_logo': get_brand_logo(),
            'terms_of_service': get_terms_of_service(),
            'social_true': any((get_fb_link(), get_ig_link(), get_x_link(), get_linkedin_link(), get_tiktok_link())),
            'fb_link': get_fb_link(),
            'ig_link': get_ig_link(),
            'x_link': get_x_link(),
            'linkedin_link': get_linkedin_link(),
            'tiktok_link': get_tiktok_link()

        }

        html_template_path = os.path.join(settings.BASE_DIR, 'apps', 'authentication', 'emails', 'generic_email.html')
        txt_template_path = os.path.join(settings.BASE_DIR, 'apps', 'authentication', 'emails', 'generic_email.txt')

        if not os.path.exists(html_template_path):
            raise FileNotFoundError(f"HTML template not found at {html_template_path}")
        if not os.path.exists(txt_template_path):
            raise FileNotFoundError(f"Text template not found at {txt_template_path}")

        with open(html_template_path, 'r', encoding='utf-8') as f:
            html_template = Template(f.read())
        html_message = html_template.render(Context(context))

        with open(txt_template_path, 'r', encoding='utf-8') as f:
            txt_template = Template(f.read())
        plain_message = txt_template.render(Context(context))

        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[user_email],
            html_message=html_message,
            fail_silently=False,
        )

    except FileNotFoundError as e:
        raise
    except Exception as e:
        print(f"Error during template rendering: {e}")
        raise
