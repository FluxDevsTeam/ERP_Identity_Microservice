from .emails import send_generic_email
from celery import shared_task, current_app
from celery.exceptions import MaxRetriesExceededError


def is_celery_healthy():
    try:
        current_app.connection().ensure_connection(max_retries=0)
        return True
    except Exception as e:
        return False


def send_email_synchronously(user_email, action=None, email_type=None, subject=None, message=None, otp=None, link=None,
                             link_text=None):
    try:
        send_generic_email(
            user_email=user_email,
            email_type=email_type,
            subject=subject,
            action=action,
            message=message,
            otp=otp,
            link=link,
            link_text=link_text
        )
        return {"status": "success", "email_type": email_type, "email": user_email}
    except Exception as e:
        return {"status": "failure", "email_type": email_type, "email": user_email, "error": str(e)}


@shared_task(bind=True, max_retries=3)
def send_generic_email_task(self, user_email, email_type, subject, action, message, otp=None, link=None,
                            link_text=None):
    try:
        valid_email_types = ['otp', 'confirmation', 'reset_link']
        if email_type not in valid_email_types:
            raise ValueError(f"Invalid email_type: must be one of {valid_email_types}")

        send_generic_email(
            user_email=user_email,
            email_type=email_type,
            subject=subject,
            action=action,
            message=message,
            otp=otp,
            link=link,
            link_text=link_text
        )
        return {"status": "success", "email_type": email_type, "email": user_email}
    except Exception as e:
        try:
            self.retry(exc=e, countdown=30)
        except MaxRetriesExceededError:
            return send_email_synchronously(
                user_email=user_email,
                email_type=email_type,
                subject=subject,
                action=action,
                message=message,
                otp=otp,
                link=link,
                link_text=link_text
            )
