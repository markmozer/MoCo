from flask import Blueprint, render_template, request, flash, redirect, url_for
from myapp.website.forms.contactform import ContactForm
from myapp.msgraphapi import MSGraphAPI
from config import Config

website_bp = Blueprint(
    'website_bp',
    __name__,
    template_folder='templates',
    static_folder='static',
)


@website_bp.route('/', methods=['GET', 'POST'])
def home():
    form = ContactForm()
    if request.method == 'POST':
        html = render_template("ws_contact_email.html", form=form)
        subject = "Thank you for reaching out to Mozer Consulting"

        mail_api = MSGraphAPI()
        mail_api.send_email(
            subject=subject,
            body=html,
            to_recipients=[request.form.get('email')],
            cc_recipients=[Config.UPN]
        )
        flash("Your message has been sent successfully!", 'success')
        return redirect(url_for('website_bp.home') + "#top")
    return render_template('ws_index.html', form=form)


@website_bp.route('/copyright')
def my_copyright():
    return render_template('ws_copyright.html')


@website_bp.route('/disclaimer')
def disclaimer():
    return render_template('ws_disclaimer.html')


@website_bp.route('/terms')
def terms():
    return render_template('ws_terms.html')


@website_bp.route('/privacy')
def privacy():
    return render_template('ws_privacy.html')
