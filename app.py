from flask import Flask, render_template, request, flash, redirect, url_for, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from selectolax.parser import HTMLParser
from urllib.parse import urlparse, urljoin
import re
import time
import json
import random
from flask_mail import Mail, Message
from email_validator import validate_email, EmailNotValidError
import phonenumbers
from phonenumbers import parse, is_valid_number, NumberParseException





app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure key

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Dummy user store (now stores any username dynamically)
users = {}

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    return User(user_id) if user_id in users else None

def extract_info(page_tree, base_url):
    info = {
        'emails': set(),
        'phone_numbers': set(),
        'addresses': set(),
        'social_media': set(),
        'company_name': None,
    }

    email_pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    phone_pattern = re.compile(r"\+?\d[\d\s\-\(\)]{7,}\d")
    address_patterns = [
        re.compile(pattern) for pattern in [
            r"\d{1,5}\s[\w\s.,-]{1,100},?\s[A-Z]{2}\s\d{5}",
            r"\d{1,5}\s[\w\s.,-]{1,100},?\s[\w\s.,-]{1,100},?\s[A-Z]{2}\s\d{5}",
            r"\d+\s[\w\s.,-]+\s[\w\s.,-]+,\s\w+\s[A-Z]{2}\s\d{5}",
        ]
    ]
    social_media_domains = {"facebook.com", "twitter.com", "linkedin.com", "instagram.com"}

    page_text = page_tree.body.text()

    # Extract emails, phone numbers, and addresses from text
    info['emails'].update(email_pattern.findall(page_text))
    info['phone_numbers'].update(phone_pattern.findall(page_text)[:2])
    for pattern in address_patterns:
        info['addresses'].update(pattern.findall(page_text))

    # Extract emails from 'mailto' links
    for node in page_tree.css('a[href^=mailto]'):
        email = node.attributes.get('href', '').split(':')[1].split('?')[0]
        info['emails'].add(email)

    # Extract social media links
    for node in page_tree.css('a[href]'):
        href = node.attributes.get('href', '')
        if href and any(domain in href for domain in social_media_domains):
            info['social_media'].add(urljoin(base_url, href))

    # Extract company name from structured data or meta tags
    for node in page_tree.css("script[type='application/ld+json']"):
        try:
            structured_data = json.loads(node.text())
            if "name" in structured_data:
                info['company_name'] = structured_data["name"]
                break
        except json.JSONDecodeError:
            continue

    if not info['company_name']:
        meta_name = page_tree.css_first('meta[property="og:site_name"]')
        if meta_name:
            info['company_name'] = meta_name.attributes.get('content', '')

    # Fallback to domain name if company name is still not found
    if not info['company_name']:
        domain = urlparse(base_url).netloc.split('.')
        if len(domain) > 1:
            business_name = domain[0].replace('www', '').replace('-', ' ').replace('_', ' ').title()
            if business_name.lower() not in ('top', '10', 'forbes', 'yelp', 'houzz', 'tripadvisor', 'angieslist', 'yellowpages', 'bbb'):
                info['company_name'] = business_name

    return {k: v for k, v in info.items() if v}

def fetch_page_content(url, headers, retries=3):
    for i in range(retries):
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return HTMLParser(response.text)
        except Exception as e:
            print(f"Attempt {i+1} failed for {url}: {e}")
            time.sleep(2)
    return None

def find_contact_or_about_page(main_tree, base_url, headers):
    keywords = {"contact", "about", "info", "reach", "email", "support", "help", "customer"}
    potential_pages = [
        urljoin(base_url, node.attributes.get('href', ''))
        for node in main_tree.css('a[href]')
        if node.attributes.get('href', '') and any(keyword in node.attributes.get('href', '').lower() for keyword in keywords)
    ]

    for full_url in potential_pages:
        page_tree = fetch_page_content(full_url, headers)
        if page_tree:
            info = extract_info(page_tree, full_url)
            if info.get('emails'):
                return info
    return {}

def is_relevant_site(domain):
    if domain is None:
        return False
    
    excluded_domains = {
        'forbes.com', 'top10.com', 'businessinsider.com', 'yelp.com', 
        'houzz.com', 'tripadvisor.com', 'angieslist.com', 'yellowpages.com', 'bbb.org',
        'craigslist.org', 'walmart.com', 'amazon.com', 'bestbuy.com', 'homedepot.com',
        'trustpilot.com', 'yellowpages.co.uk', 'europages.com', 'gelbe-seiten.de', 'apartmentfinder.com',
        'olx.com.br', 'mercadolivre.com.br', 'zapimoveis.com.br', 'submarino.com.br', 'buscapÃ©.com.br',
        'gumtree.co.za', 'yellowpages.co.za', 'craigslist.co.za', 'africabusinessdirectory.com', 'za.yellowpages.com',
        'olx.in', 'justdial.com', 'sulekha.com', 'quikr.com', 'yahoo.co.jp', 'rakuten.co.jp',
        't.co', 'taobao.com', 'alibaba.com', 'jd.com', 'kaiser.com', 'kakaku.com'
    }
    return domain.lower() not in excluded_domains

@app.route('/search', methods=['POST'])
@login_required
def search():
    query = request.form.get('business_type')
    if not query:
        return redirect(url_for('leads_generator'))

    search_url = f"https://www.google.com/search?q={query}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    response = requests.get(search_url, headers=headers)
    soup = HTMLParser(response.text)

    leads = []

    for g in soup.css('div.g'):
        title_node = g.css_first('h3')
        link_node = g.css_first('a')
        snippet_node = g.css_first('span.aCOpRe')
        date_node = g.css_first('span.f')
        domain = None
        
        if link_node:
            domain = urlparse(link_node.attributes.get('href', '')).netloc

        if title_node and link_node and domain and is_relevant_site(domain):
            page_tree = fetch_page_content(link_node.attributes.get('href', ''), headers)
            if page_tree:
                base_url = urljoin(link_node.attributes.get('href', ''), '/')
                info = extract_info(page_tree, base_url)
                if not info.get('emails'):
                    contact_about_info = find_contact_or_about_page(page_tree, base_url, headers)
                    if contact_about_info:
                        info['emails'] = contact_about_info.get('emails', set())

                leads.append({
                    'link': link_node.attributes.get('href', ''),
                    'info': info
                })

    return render_template('leads_generator.html', title="Leads Generator", leads=leads)

@app.route('/')
@login_required
def index():
    return render_template('index.html', leads=[])

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')    

@app.route('/leads-generator')
@login_required
def leads_generator():
    return render_template('leads_generator.html', title="Leads Generator")

@app.route('/find-contacts')
@login_required
def find_contacts():
    return render_template('find_contacts.html', title="Find Contacts")

@app.route('/social_media_lookup')
@login_required
def social_media_lookup():
    return render_template('social_media_lookup.html')

@app.route('/ai_lead_scoring')
@login_required
def ai_lead_scoring():
    return render_template('ai_lead_scoring.html')

@app.route('/help_center')
@login_required
def help_center():
    return render_template('help_center.html')    



def parse_leads(leads_text):
    """
    Parses lead text into a list of lead information dictionaries.
    :param leads_text: A string containing lead details.
    :return: A list of dictionaries, each containing lead details.
    """
    # Split the leads text by "Visit Website", which is a unique identifier for the end of each lead
    lead_entries = leads_text.strip().split('Visit Website')
    leads = []

    for entry in lead_entries:
        if not entry.strip():
            continue
        
        lead_info = {}
        
        # Extract name (first line)
        name_match = re.match(r'^([^\n]+)', entry.strip())
        if name_match:
            lead_info['name'] = name_match.group(1).strip()
        
        # Extract emails
        emails_match = re.search(r'Email:\s*(.*)', entry)
        if emails_match:
            lead_info['emails'] = [email.strip() for email in emails_match.group(1).split(',')]

        # Extract phone numbers
        phones_match = re.search(r'Phone No:\s*(.*)', entry)
        if phones_match:
            lead_info['phone_numbers'] = [phone.strip() for phone in phones_match.group(1).split(',')]

        # Extract address
        address_match = re.search(r'Address:\s*(.*)', entry)
        if address_match:
            lead_info['address'] = address_match.group(1).strip()
        else:
            lead_info['address'] = 'None'

        # Extract social media links
        social_media_match = re.search(r'Social Media:\s*(.*)', entry)
        if social_media_match:
            lead_info['social_media'] = [link.strip() for link in social_media_match.group(1).split(',')]
        
        leads.append(lead_info)

    return leads



def score_lead(lead_info):
    """
    Generates a score, category, and conversion rate for a lead based on various criteria.
    :param lead_info: A dictionary containing lead details (name, emails, phone_numbers, address, social_media).
    :return: A dictionary with the score, category, and conversion rate for the lead.
    """
    score = 0

    # Scoring based on the number of emails
    if 'emails' in lead_info and lead_info['emails']:
        score += len(lead_info['emails']) * 10

    # Scoring based on the number of phone numbers
    if 'phone_numbers' in lead_info and lead_info['phone_numbers']:
        score += len(lead_info['phone_numbers']) * 5

    # Scoring based on presence of an address
    if 'address' in lead_info and lead_info['address'] and lead_info['address'] != 'None':
        score += 15

    # Scoring based on the number of social media links
    if 'social_media' in lead_info and lead_info['social_media']:
        score += len(lead_info['social_media']) * 10

    # Determine category based on score
    if score >= 50:
        category = 'High'
        conversion_rate = 90
    elif 30 <= score < 50:
        category = 'Medium'
        conversion_rate = 60
    else:
        category = 'Low'
        conversion_rate = 30

    return {
        'score': score,
        'category': category,
        'conversion_rate': conversion_rate
    }


@app.route('/analyze-leads', methods=['POST'])
@login_required
def analyze_leads():
    leads_text = request.form.get('leads')
    file = request.files.get('file')

    if file:
        leads_text = file.read().decode('utf-8')

    results = []
    if leads_text:
        # Simulate AI processing delay
        delay = random.uniform(2, 5)  # Random delay between 2 to 5 seconds
        time.sleep(delay)
        
        feedback = "AI is analyzing the leads. This may take a moment..."
        print(feedback)  # This can be logged or shown to the user.

        # Parse the leads
        lead_infos = parse_leads(leads_text)

        # Process each lead
        for lead_info in lead_infos:
            # AI-like decision making
            score_info = score_lead(lead_info)
            ai_feedback = f"AI has determined that the lead '{lead_info.get('name', 'No Name')}' has a {score_info['category']} potential."

            # Example of adding variability in scoring
            score_info['score'] += random.randint(-5, 5)

            # Append to results
            results.append({
                'name': lead_info.get('name', 'No Name'),
                'score': score_info['score'],
                'category': score_info['category'],
                'conversion_rate': score_info['conversion_rate'],
                'email': ', '.join(lead_info.get('emails', [])),
                'phone': ', '.join(lead_info.get('phone_numbers', [])),
                'address': lead_info.get('address', 'None'),
                'social_media': ', '.join(lead_info.get('social_media', [])),
                'ai_feedback': ai_feedback
            })

    return render_template('ai_lead_scoring.html', results=results)




@app.route('/search-company-contacts', methods=['POST'])
@login_required
def search_company_contacts():
    query = request.form.get('company_name')
    if not query:
        return redirect(url_for('find_contacts'))

    search_terms = ["ceo linkedin", "cto linkedin", "founder linkedin", "partner linkedin", "investor linkedin", "leadership linkedin"]
    search_queries = [f"{query} {term}" for term in search_terms]
    contacts = []
    unique_contacts = set()  # To track unique LinkedIn profiles

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    for search_query in search_queries:
        search_url = f"https://www.google.com/search?q={search_query}"
        try:
            response = requests.get(search_url, headers=headers)
            response.raise_for_status()  # Ensure we get a valid response
            soup = HTMLParser(response.text)

            for g in soup.css('div.g'):
                title_node = g.css_first('h3')
                link_node = g.css_first('a')

                if link_node:
                    href = link_node.attributes.get('href', '')
                    if not href:
                        continue

                    domain = urlparse(href).netloc

                    if title_node and domain and is_relevant_site(domain):
                        page_tree = fetch_page_content(href, headers)
                        if page_tree:
                            people = extract_people_info(page_tree)
                            for person in people:
                                if person['linkedin'] not in unique_contacts:
                                    contacts.append(person)
                                    unique_contacts.add(person['linkedin'])

        except Exception as e:
            print(f"An error occurred: {e}")
            continue

    # Filter out contacts without LinkedIn profile links (optional, if needed)
    contacts_with_profiles = [contact for contact in contacts if contact['linkedin']]

    return render_template('find_contacts.html', title="Company Contacts", contacts=contacts_with_profiles)


def extract_people_info(page_tree):
    people_info = []

    if not page_tree or not page_tree.body:
        return people_info

    # Patterns to identify people and their positions
    people_patterns = [
        re.compile(r"([A-Z][a-z]+ [A-Z][a-z]+)\s*(CEO|CTO|Founder|Partner|Investor|President|Vice President|Manager|Director|Head of [a-zA-Z]+|Lead [a-zA-Z]+)", re.IGNORECASE)
    ]

    # Extract people info from the text
    page_text = page_tree.body.text() if page_tree.body else ""

    for pattern in people_patterns:
        matches = pattern.findall(page_text)
        for match in matches:
            name, position = match
            linkedin_profile = find_linkedin_profile(page_tree, name)
            if linkedin_profile:
                people_info.append({
                    'name': name,
                    'position': position,
                    'linkedin': linkedin_profile
                })

    return people_info


def find_linkedin_profile(page_tree, name):
    if not page_tree:
        return None

    linkedin_profile = None
    for node in page_tree.css('a[href]'):
        href = node.attributes.get('href', '')
        if href and 'linkedin.com/in/' in href and name.lower().replace(' ', '-') in href.lower():
            linkedin_profile = href
            break
    return linkedin_profile


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Simplified login to accept any username/password
        if username and password:
            # Add user to the session
            if username not in users:
                users[username] = generate_password_hash(password)
            user = User(username)
            login_user(user)
            return redirect(url_for('index'))
        
        return 'Invalid credentials', 401
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))



@app.route('/social-media-search', methods=['POST'])
@login_required
def perform_social_media_search():
    handle = request.form.get('social_media_handle')
    if not handle:
        return redirect(url_for('render_social_media_search'))

    search_url = f"https://www.google.com/search?q={handle} site:linkedin.com OR site:twitter.com OR site:instagram.com OR site:facebook.com OR site:tiktok.com OR site:pinterest.com OR site:youtube.com"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    response = requests.get(search_url, headers=headers)
    soup = HTMLParser(response.text)

    leads = []

    for g in soup.css('div.g'):
        link_node = g.css_first('a')
        snippet_node = g.css_first('span.aCOpRe')
        
        if link_node:
            profile_url = link_node.attributes.get('href', '')
            if any(platform in profile_url for platform in ['linkedin.com', 'twitter.com', 'instagram.com', 'facebook.com', 'tiktok.com', 'pinterest.com', 'youtube.com']):
                leads.append({
                    'social_media_handle': handle,
                    'profile_url': profile_url
                })

    return render_template('social_media_lookup.html', title="Social Media Search", leads=leads)

@app.route('/social-media-search')
@login_required
def render_social_media_search():
    return render_template('social_media_lookup.html', leads=None)


# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Default SMTP server, can be overridden
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = None  # Set None to allow dynamic configuration
app.config['MAIL_PASSWORD'] = None

mail = Mail(app)


@app.route('/bulk_email_sender', methods=['GET', 'POST'])
@login_required
def bulk_email_sender():
    if request.method == 'POST':
        email_subject = request.form['email_subject']
        email_body = request.form['email_body']
        email_list = request.form['email_list'].split(',')
        smtp_server = request.form['smtp_server']
        smtp_port = request.form['smtp_port']
        smtp_username = request.form['smtp_username']
        smtp_password = request.form['smtp_password']

        # Update app config with user's SMTP details
        app.config['MAIL_SERVER'] = smtp_server
        app.config['MAIL_PORT'] = int(smtp_port)
        app.config['MAIL_USERNAME'] = smtp_username
        app.config['MAIL_PASSWORD'] = smtp_password

        try:
            with mail.connect() as conn:
                for email in email_list:
                    msg = Message(subject=email_subject,
                                  body=email_body,
                                  sender=smtp_username,
                                  recipients=[email.strip()])
                    conn.send(msg)
                    
            flash('Emails have been sent successfully!', 'success')
            return redirect(url_for('bulk_email_sender'))
        except Exception as e:
            flash(f'Failed to send emails. Error: {str(e)}', 'danger')
            return redirect(url_for('bulk_email_sender'))

    # Handle GET request: render the form
    return render_template('bulk_email_sender.html', title="Bulk Email Sender")


@app.route('/email-validation', methods=['GET', 'POST'])
@login_required
def email_validation():
    if request.method == 'POST':
        email_addresses = request.form['email_addresses'].splitlines()
        validation_results = []

        for email in email_addresses:
            email = email.strip()
            if email:  # Check if the email string is not empty
                try:
                    # Validate email without DNS checks
                    valid = validate_email(email, check_deliverability=False)
                    validation_results.append({
                        'email': email,
                        'status': 'Valid',
                        'status_class': 'text-success'
                    })
                except EmailNotValidError:
                    validation_results.append({
                        'email': email,
                        'status': 'Invalid',
                        'status_class': 'text-danger'
                    })

        return jsonify(validation_results)

    # Handle GET request: render the form
    return render_template('email_validation.html', title="Email Validation")


@app.route('/phone-validation', methods=['GET', 'POST'])
@login_required
def phone_validation():
    if request.method == 'POST':
        phone_numbers = request.form['phone_numbers'].splitlines()
        country_code = request.form.get('country_code', '').strip()
        validation_results = []

        for number in phone_numbers:
            number = number.strip()
            if number:
                try:
                    parsed_number = phonenumbers.parse(number, country_code if country_code else None)
                    if phonenumbers.is_valid_number(parsed_number):
                        validation_results.append({
                            'number': number,
                            'status': 'Valid',
                            'status_class': 'text-success'
                        })
                    else:
                        validation_results.append({
                            'number': number,
                            'status': 'Invalid',
                            'status_class': 'text-danger'
                        })
                except phonenumbers.NumberParseException:
                    validation_results.append({
                        'number': number,
                        'status': 'Invalid',
                        'status_class': 'text-danger'
                    })

        return jsonify(validation_results)

    return render_template('phone_validation.html', title="Phone Number Validation")



if __name__ == '__main__':
    app.run(debug=True)
