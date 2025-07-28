from flask import Flask, render_template, request, session, redirect, url_for, jsonify
import uuid
import json
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'salesstorm-ai-secret-key-change-in-production')

# Sample data for niches and presets
NICHES = {
    'ai-tools': 'AI Tools',
    'local-biz': 'Local Business',
    'crypto': 'Cryptocurrency',
    'side-hustles': 'Side Hustles'
}

# In-memory storage for bonus pages (in production, use Redis or database)
bonus_pages = {}

@app.route('/')
def index():
    """Main dashboard with feature overview"""
    return render_template('index.html', niches=NICHES)

# Make niches available to all templates
@app.context_processor
def inject_globals():
    return dict(niches=NICHES)

@app.route('/ai-storm', methods=['GET', 'POST'])
def ai_storm():
    """AI Storm Builder - Generate sales pages and emails"""
    if request.method == 'POST':
        niche = request.form.get('niche')
        offer_link = request.form.get('offer_link')
        
        # Store in session
        session['ai_storm_data'] = {
            'niche': niche,
            'offer_link': offer_link,
            'generated_at': datetime.now().isoformat()
        }
        
        # Generate dummy content (replace with OpenAI API calls)
        profit_page = generate_profit_page(niche, offer_link)
        bonus_page = generate_bonus_page(niche)
        follow_up_emails = generate_follow_up_emails(niche, offer_link)
        
        return render_template('ai_storm_results.html', 
                             profit_page=profit_page,
                             bonus_page=bonus_page,
                             emails=follow_up_emails,
                             niche=niche,
                             offer_link=offer_link)
    
    return render_template('ai_storm.html', niches=NICHES)

@app.route('/activator', methods=['GET', 'POST'])
def commission_activator():
    """Commission Activator System - High-conversion pages"""
    if request.method == 'POST':
        affiliate_link = request.form.get('affiliate_link')
        niche = request.form.get('niche')
        
        # Generate activation page
        activation_data = {
            'affiliate_link': affiliate_link,
            'niche': niche,
            'scarcity_timer': 24,  # 24 hours
            'bonuses': get_niche_bonuses(niche),
            'page_id': str(uuid.uuid4())
        }
        
        return render_template('activator_page.html', **activation_data)
    
    return render_template('activator.html', niches=NICHES)

@app.route('/bonus/<bonus_id>')
def bonus_delivery(bonus_id):
    """Bonus Delivery Vault - Unique bonus pages with countdown"""
    # Check if bonus page exists
    if bonus_id not in bonus_pages:
        # Create new bonus page
        bonus_pages[bonus_id] = {
            'id': bonus_id,
            'created_at': datetime.now(),
            'unlock_time': datetime.now() + timedelta(minutes=5),  # 5 minute delay
            'bonuses': get_default_bonuses(),
            'accessed': False
        }
    
    bonus_data = bonus_pages[bonus_id]
    is_unlocked = datetime.now() >= bonus_data['unlock_time']
    
    return render_template('bonus.html', 
                         bonus_data=bonus_data,
                         is_unlocked=is_unlocked,
                         bonus_id=bonus_id)

@app.route('/promoter', methods=['GET', 'POST'])
def salesstorm_promoter():
    """SalesStorm AI Promoter - Generate marketing content"""
    if request.method == 'POST':
        niche = request.form.get('niche')
        offer = request.form.get('offer')
        
        # Generate promotional content
        content = {
            'broadcast_email': generate_broadcast_email(niche, offer),
            'social_post': generate_social_post(niche, offer),
            'video_script': generate_video_script(niche, offer)
        }
        
        return render_template('promoter_results.html', 
                             content=content,
                             niche=niche,
                             offer=offer)
    
    return render_template('promoter.html', niches=NICHES)

@app.route('/niche/<niche_name>')
def niche_presets(niche_name):
    """Niche Storm Presets - Pre-built templates"""
    if niche_name not in NICHES:
        return redirect(url_for('index'))
    
    presets = get_niche_presets(niche_name)
    return render_template('niche.html', 
                         niche_name=niche_name,
                         niche_display=NICHES[niche_name],
                         presets=presets)

@app.route('/api/generate-bonus-link')
def generate_bonus_link():
    """API endpoint to generate unique bonus links"""
    bonus_id = str(uuid.uuid4())
    bonus_url = url_for('bonus_delivery', bonus_id=bonus_id, _external=True)
    return jsonify({'bonus_id': bonus_id, 'bonus_url': bonus_url})

# Helper functions for content generation
def generate_profit_page(niche, offer_link):
    """Generate profit page content"""
    return {
        'headline': f"🚀 Revolutionary {NICHES.get(niche, 'Business')} Solution That's Changing Everything!",
        'subheadline': f"Discover the Secret {NICHES.get(niche, 'Business')} Strategy That's Generated Over $10M+ in Sales",
        'benefits': [
            f"Automated {NICHES.get(niche, 'Business')} systems that work 24/7",
            "Step-by-step blueprint for immediate results",
            "Done-for-you templates and resources",
            "Private mastermind access worth $2,997"
        ],
        'cta_text': "Get Instant Access Now!",
        'offer_link': offer_link,
        'urgency': "Limited Time: Only 24 Hours Left!"
    }

def generate_bonus_page(niche):
    """Generate bonus page content"""
    return {
        'title': f"Exclusive {NICHES.get(niche, 'Business')} Bonuses",
        'bonuses': get_niche_bonuses(niche),
        'total_value': "$4,997"
    }

def generate_follow_up_emails(niche, offer_link):
    """Generate follow-up email sequence"""
    return [
        {
            'subject': f"Your {NICHES.get(niche, 'Business')} Journey Starts Now...",
            'preview': "Don't let this opportunity slip away",
            'body': f"Hey there!\n\nYou showed interest in our {NICHES.get(niche, 'business')} solution, and I wanted to personally reach out...\n\n[Continue with email content]\n\nGet started here: {offer_link}"
        },
        {
            'subject': f"[URGENT] {NICHES.get(niche, 'Business')} Deadline Approaching",
            'preview': "Only hours left to secure your spot",
            'body': f"This is it...\n\nIn just a few hours, the doors close on our exclusive {NICHES.get(niche, 'business')} program...\n\n[Continue with urgency email]\n\nSecure your spot: {offer_link}"
        },
        {
            'subject': f"Final Notice: {NICHES.get(niche, 'Business')} Opportunity Closing",
            'preview': "Last chance to join",
            'body': f"I hate to be the bearer of bad news, but...\n\nThis is your absolute final chance to get access to our {NICHES.get(niche, 'business')} system.\n\n[Final email content]\n\nLast chance: {offer_link}"
        }
    ]

def generate_broadcast_email(niche, offer):
    """Generate broadcast email content"""
    return {
        'subject': f"🔥 New {NICHES.get(niche, 'Business')} Breakthrough!",
        'body': f"Hey [First Name],\n\nI just discovered something incredible in the {NICHES.get(niche, 'business')} space...\n\n{offer}\n\nThis could be exactly what you've been looking for!\n\nCheck it out here: [LINK]\n\nTo your success,\n[Your Name]"
    }

def generate_social_post(niche, offer):
    """Generate social media post"""
    return {
        'facebook': f"🚨 GAME CHANGER ALERT! 🚨\n\nJust found this incredible {NICHES.get(niche, 'business')} opportunity:\n\n{offer}\n\nWho else is ready to level up? 💪\n\n#SalesStorm #{niche.replace('-', '').title()}",
        'twitter': f"🔥 This {NICHES.get(niche, 'business')} breakthrough is insane!\n\n{offer[:100]}...\n\nThread below 👇\n\n#{niche.replace('-', '').title()} #entrepreneur"
    }

def generate_video_script(niche, offer):
    """Generate video script"""
    return {
        'hook': f"If you're in the {NICHES.get(niche, 'business')} space, you NEED to see this...",
        'content': f"I just came across this {offer} and it's honestly blowing my mind...",
        'cta': "Link in bio to check it out - but don't wait, this won't be available forever!"
    }

def get_niche_bonuses(niche):
    """Get bonuses for specific niche"""
    bonus_sets = {
        'ai-tools': [
            {'name': 'AI Prompt Library (500+ Prompts)', 'value': '$497'},
            {'name': 'ChatGPT Business Automation', 'value': '$297'},
            {'name': 'AI Content Creation Masterclass', 'value': '$997'}
        ],
        'local-biz': [
            {'name': 'Local SEO Domination Guide', 'value': '$397'},
            {'name': 'Google My Business Optimization', 'value': '$297'},
            {'name': 'Local Lead Generation Scripts', 'value': '$497'}
        ],
        'crypto': [
            {'name': 'Crypto Trading Signals (30 days)', 'value': '$997'},
            {'name': 'DeFi Investment Strategies', 'value': '$697'},
            {'name': 'NFT Profit Blueprint', 'value': '$397'}
        ],
        'side-hustles': [
            {'name': '50 Profitable Side Hustle Ideas', 'value': '$297'},
            {'name': 'Passive Income Automation', 'value': '$497'},
            {'name': 'Online Business Launch Kit', 'value': '$397'}
        ]
    }
    return bonus_sets.get(niche, bonus_sets['side-hustles'])

def get_default_bonuses():
    """Get default bonus package"""
    return [
        {'name': 'SalesStorm AI Training Course', 'value': '$1,997'},
        {'name': 'High-Converting Templates Pack', 'value': '$497'},
        {'name': 'Private Mastermind Access', 'value': '$2,997'},
        {'name': '1-on-1 Strategy Session', 'value': '$497'}
    ]

def get_niche_presets(niche):
    """Get preset templates for niche"""
    return {
        'templates': {
            'sales_pages': 3,
            'email_sequences': 5,
            'bonus_packages': 2,
            'social_posts': 10
        },
        'featured': f"Complete {NICHES.get(niche, 'Business')} Marketing System",
        'description': f"Everything you need to dominate the {NICHES.get(niche, 'business')} market"
    }

if __name__ == '__main__':
    print("🚀 Starting SalesStorm AI...")
    print("📝 Access the app at: http://localhost:5000")
    print("🔧 All features are ready to use!")
    app.run(debug=True, host='0.0.0.0', port=5000)
