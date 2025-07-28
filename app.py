from flask import Flask, render_template, request, jsonify, session
import json
import random
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'salesstorm_ai_secret_key_2024'

# Fake data for dashboard stats
def get_dashboard_stats():
    return {
        'ai_funnels': random.randint(15, 45),
        'links_activated': random.randint(8, 25),
        'bonuses_delivered': random.randint(120, 350),
        'social_posts': random.randint(25, 75),
        'niches_deployed': random.randint(5, 12)
    }

# Fake AI copy generator
def generate_ai_copy(niche, offer_type="funnel"):
    copy_templates = {
        "funnel": [
            f"🚀 Revolutionary {niche} System Unleashed! This breakthrough method is transforming ordinary people into {niche} experts in just 30 days...",
            f"💡 The Secret {niche} Formula That's Breaking The Internet! Industry insiders don't want you to know this one simple trick...",
            f"⚡ Discover the Underground {niche} Method That's Generated Over $1M+ This Year! Limited time access..."
        ],
        "email": [
            f"Subject: This {niche} secret changed everything...\n\nHey [Name],\n\nI wasn't going to share this, but...\n\nA small group of {niche} experts have been quietly using this method to generate massive results.\n\nAnd today, I'm pulling back the curtain.\n\n[Your Link Here]\n\nDon't wait - this won't be available forever.\n\nBest,\n[Your Name]",
            f"Subject: 24 hours left for {niche} breakthrough\n\nQuick question...\n\nWould you like to discover the exact {niche} system that's helped 1,000+ people achieve their goals?\n\nI thought so.\n\n[Your Link Here]\n\nBut hurry - access closes in 24 hours.\n\nTo your success,\n[Your Name]"
        ],
        "social": [
            f"🔥 This {niche} method just blew my mind! Who else is ready to level up? #Success #{niche.replace(' ', '')}",
            f"💯 Just discovered the game-changing {niche} strategy everyone's talking about! Link in bio 👆",
            f"⚡ When {niche} meets AI magic... incredible things happen! Who's ready to transform their results? 🚀"
        ]
    }
    return random.choice(copy_templates.get(offer_type, copy_templates["funnel"]))

@app.route('/')
def dashboard():
    return render_template('dashboard.html', stats=get_dashboard_stats())

@app.route('/api/dashboard')
def api_dashboard():
    return jsonify({'stats': get_dashboard_stats()})

@app.route('/builder')
def builder():
    return render_template('builder.html')

@app.route('/api/builder', methods=['POST'])
def api_builder():
    data = request.get_json()
    niche = data.get('niche', 'Online Business')
    offer_link = data.get('offer_link', '')
    
    # Generate AI copy
    ai_copy = generate_ai_copy(niche)
    
    # Simulate funnel creation
    funnel_data = {
        'id': random.randint(1000, 9999),
        'niche': niche,
        'offer_link': offer_link,
        'ai_copy': ai_copy,
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
        'status': 'Active'
    }
    
    return jsonify({
        'success': True,
        'message': 'AI Funnel Created Successfully!',
        'funnel': funnel_data
    })

@app.route('/activator')
def activator():
    return render_template('activator.html')

@app.route('/api/activator', methods=['POST'])
def api_activator():
    data = request.get_json()
    affiliate_link = data.get('affiliate_link', '')
    
    # Generate DFY promo page
    promo_data = {
        'id': random.randint(1000, 9999),
        'affiliate_link': affiliate_link,
        'promo_url': f"https://salesstorm-ai.com/promo/{random.randint(1000, 9999)}",
        'template_type': 'High-Converting VSL',
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M')
    }
    
    return jsonify({
        'success': True,
        'message': 'Commission Link Activated!',
        'promo': promo_data
    })

@app.route('/vault')
def vault():
    bonuses = [
        {'id': 1, 'name': 'AI Copywriting Masterclass', 'value': '$997', 'type': 'Video Course'},
        {'id': 2, 'name': 'High-Converting Email Templates', 'value': '$497', 'type': 'Template Pack'},
        {'id': 3, 'name': 'Social Media Content Calendar', 'value': '$297', 'type': 'Spreadsheet'},
        {'id': 4, 'name': 'Funnel Blueprint Collection', 'value': '$697', 'type': 'PDF Guide'},
        {'id': 5, 'name': 'AI Prompt Library (500+)', 'value': '$397', 'type': 'Database'},
        {'id': 6, 'name': 'Traffic Generation Secrets', 'value': '$797', 'type': 'Video Series'}
    ]
    return render_template('vault.html', bonuses=bonuses)

@app.route('/promoter')
def promoter():
    return render_template('promoter.html')

@app.route('/api/promoter', methods=['POST'])
def api_promoter():
    data = request.get_json()
    niche = data.get('niche', 'Online Business')
    offer_desc = data.get('offer_description', '')
    
    # Generate AI emails and social posts
    emails = [generate_ai_copy(niche, "email") for _ in range(3)]
    social_posts = [generate_ai_copy(niche, "social") for _ in range(5)]
    
    return jsonify({
        'success': True,
        'message': 'AI Content Generated!',
        'emails': emails,
        'social_posts': social_posts
    })

@app.route('/niches')
def niches():
    niche_presets = [
        {
            'name': 'Make Money Online',
            'description': 'Affiliate marketing, drop shipping, digital products',
            'templates': 15,
            'conversion_rate': '8.5%'
        },
        {
            'name': 'Freelancing & Services',
            'description': 'Writing, design, development, consulting',
            'templates': 12,
            'conversion_rate': '7.2%'
        },
        {
            'name': 'AI Tools & Software',
            'description': 'AI automation, productivity tools, SaaS',
            'templates': 18,
            'conversion_rate': '9.1%'
        },
        {
            'name': 'Local Business',
            'description': 'Restaurants, services, retail, real estate',
            'templates': 10,
            'conversion_rate': '6.8%'
        },
        {
            'name': 'Health & Fitness',
            'description': 'Weight loss, supplements, workout programs',
            'templates': 14,
            'conversion_rate': '7.9%'
        },
        {
            'name': 'Personal Development',
            'description': 'Self-help, productivity, mindset coaching',
            'templates': 11,
            'conversion_rate': '7.3%'
        }
    ]
    return render_template('niches.html', niches=niche_presets)

@app.route('/api/niches/<niche_name>')
def api_niche_preview(niche_name):
    # Generate preview template for selected niche
    preview_data = {
        'niche': niche_name.replace('-', ' ').title(),
        'template_preview': generate_ai_copy(niche_name.replace('-', ' ')),
        'features': [
            'High-converting headlines',
            'Proven sales copy',
            'Mobile-optimized design',
            'A/B tested elements',
            'One-click deployment'
        ]
    }
    
    return jsonify(preview_data)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
