# import os
# from django.shortcuts import render
# from django.template import Template, Context
# from django.utils.functional import SimpleLazyObject
# from ..ecommerce_admin.models import OrganizationSettings, DeveloperSettings

# BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# organization_settings = SimpleLazyObject(
#     lambda: OrganizationSettings.objects.first())
# organization = SimpleLazyObject(lambda: {
#     'support_phone_number': getattr(organization_settings, 'phone_number', None),
#     'support_email': getattr(organization_settings, 'customer_support_email', None),
#     'brand_logo': getattr(organization_settings, 'brand_logo', None),
#     'facebook': getattr(organization_settings, 'facebook', None),
#     'instagram': getattr(organization_settings, 'instagram', None),
#     'x': getattr(organization_settings, 'twitter', None),
#     'linkedin': getattr(organization_settings, 'linkedin', None),
#     'tiktok': getattr(organization_settings, 'tiktok', None),
# })

# SUPPORT_PHONE_NUMBER = organization['support_phone_number']
# # to be implemented when we have url leading directly to brand logo
# SUPPORT_EMAIL = organization['support_email']
# BRAND_LOGO = organization['brand_logo']
# FB_LINK = organization['facebook']
# IG_LINK = organization['instagram']
# X_LINK = organization['x']
# LINKEDIN_LINK = organization['linkedin']
# TIKTOK_LINK = organization['tiktok']


# developer_settings = SimpleLazyObject(
#     lambda: DeveloperSettings.objects.first())
# developer = SimpleLazyObject(lambda: {
#     'brand_name': getattr(developer_settings, 'brand_name', None),
#     'terms_of_service': getattr(developer_settings, 'terms_of_service', None)
# })

# BRAND_NAME = developer['brand_name']
# TERMS_OF_SERVICE = developer['terms_of_service']


# def test_email(request):
#     ''''
#     This function is used to test the email template rendering.
#     add this path to your url and test it in the browser.

#         path('test-template/', template_test.test_email, name='test_template'),

#     '''
#     context = {
#         'support_email': SUPPORT_EMAIL,
#         'support_phone_number': SUPPORT_PHONE_NUMBER,
#         'brand_name': BRAND_NAME,
#         'brand_logo': BRAND_LOGO,
#         'terms_of_service': TERMS_OF_SERVICE,
#         'social_true': any((FB_LINK, IG_LINK, X_LINK, X_LINK, LINKEDIN_LINK, TIKTOK_LINK)),
#         'fb_link': FB_LINK,
#         'ig_link': IG_LINK,
#         'x_link': X_LINK,
#         'linkedin_link': LINKEDIN_LINK,
#         'tiktok_link': TIKTOK_LINK
#     }

#     html_template_path = os.path.join(
#         BASE_DIR, 'emails', 'generic_email.html')
#     txt_template_path = os.path.join(
#         BASE_DIR, 'emails', 'generic_email.txt')

#     with open(html_template_path, 'r', encoding='utf-8') as f:
#         html_template = Template(f.read())
#     html_message = html_template.render(Context(context))

#     with open(txt_template_path, 'r', encoding='utf-8') as f:
#         txt_template = Template(f.read())
#     plain_message = txt_template.render(Context(context))

#     send_mail(
#         subject=f"Ecommerce App Template - Refund Confirmation",
#         message=plain_message,
#         from_email=settings.EMAIL_HOST_USER,
#         recipient_list=['test@gmail.com'],
#         html_message=html_message,
#         fail_silently=False,
#     )
#     return render(request, 'authentication/emails/generic_email.html', context)
