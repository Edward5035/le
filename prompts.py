"""
OpenAI Prompt Templates for SalesStorm AI
Contains all prompt templates for generating marketing content
"""

# Profit Page Generation Prompts
PROFIT_PAGE_PROMPT = """
You are an expert sales copywriter with 20+ years of experience in high-converting sales pages.
Create a compelling profit page for the following:

Niche: {niche}
Offer Link: {offer_link}
Offer Description: {offer_description}

Generate a profit page with:
1. A powerful headline that creates curiosity and urgency
2. A compelling subheadline that reinforces the main benefit
3. 4-6 key benefits that speak to the target audience's pain points
4. A strong call-to-action phrase
5. An urgency statement that creates FOMO

Make it conversion-focused, benefit-driven, and emotionally engaging.
Use power words and psychological triggers.
Target audience: {niche} enthusiasts and beginners.

Format as JSON with keys: headline, subheadline, benefits, cta_text, urgency
"""

BONUS_PAGE_PROMPT = """
You are a bonus creation expert who knows how to stack value and create irresistible offers.
Create an exclusive bonus package for the following:

Niche: {niche}
Main Offer: {offer_description}

Generate a bonus page with:
1. A compelling title for the bonus section
2. 3-5 high-value bonuses that complement the main offer
3. Each bonus should have a name and perceived value
4. Total stack value calculation

Make bonuses feel exclusive, valuable, and directly related to helping them succeed faster.
Each bonus should solve a specific problem or accelerate results.

Format as JSON with keys: title, bonuses (array with name/value), total_value
"""

# Email Sequence Generation Prompts
FOLLOW_UP_EMAIL_PROMPT = """
You are an email marketing expert specializing in high-converting follow-up sequences.
Create a 3-email follow-up sequence for:

Niche: {niche}
Offer: {offer_description}
Offer Link: {offer_link}

Email 1: Relationship building + soft introduction
Email 2: Value delivery + urgency building
Email 3: Final call + strong scarcity

Each email needs:
- Compelling subject line
- Preview text
- Email body (conversational tone, benefit-focused)
- Clear CTA

Make emails feel personal, valuable, and progressively more urgent.
Use storytelling and social proof where appropriate.

Format as JSON array with objects containing: subject, preview, body
"""

# Promotional Content Prompts
BROADCAST_EMAIL_PROMPT = """
You are a master email marketer who creates viral promotional emails.
Create a broadcast email for:

Niche: {niche}
Offer: {offer}
Tone: {tone}
Urgency Level: {urgency_level}

Generate:
1. An attention-grabbing subject line
2. A conversational email body that builds curiosity
3. Include social proof and benefits
4. Strong call-to-action
5. Urgency if specified

Keep it {tone} and make it feel like it's from a trusted friend.
Length: 200-300 words.

Format as JSON with keys: subject, body
"""

SOCIAL_POST_PROMPT = """
You are a social media marketing expert who creates viral content.
Create social media posts for:

Niche: {niche}
Offer: {offer}
Platform: {platform}
Include Emojis: {use_emojis}
Add Hooks: {add_hooks}

Generate platform-specific content:
- Facebook: Longer form, storytelling, engagement-focused
- Twitter: Concise, thread-worthy, hashtag optimized
- LinkedIn: Professional, authority-building, industry-focused

Include relevant hashtags and call-to-action.
Make it shareable and engaging.

Format as JSON with keys for each platform
"""

VIDEO_SCRIPT_PROMPT = """
You are a video marketing expert who creates engaging short-form video scripts.
Create a video script for:

Niche: {niche}
Offer: {offer}
Video Type: Short-form (30-60 seconds)
Target: {target_audience}

Generate:
1. Hook (first 3 seconds) - attention-grabbing opener
2. Main content (problem/solution/benefit)
3. Call-to-action (clear next step)

Script should be:
- Fast-paced and engaging
- Problem/solution focused
- Benefit-driven
- Include visual cues [in brackets]

Format as JSON with keys: hook, content, cta
"""

# Niche-Specific Prompts
NICHE_CONTENT_PROMPTS = {
    'ai-tools': {
        'pain_points': [
            'Struggling with productivity and efficiency',
            'Overwhelmed by manual tasks',
            'Missing out on AI opportunities',
            'Competitors getting ahead with AI'
        ],
        'benefits': [
            'Automate repetitive tasks',
            'Increase productivity by 300%',
            'Stay ahead of the competition',
            'Save hours of manual work daily'
        ],
        'keywords': ['AI', 'automation', 'productivity', 'efficiency', 'future-proof']
    },
    'local-biz': {
        'pain_points': [
            'Not enough local customers',
            'Invisible on Google searches',
            'Losing to big chain competitors',
            'Struggling with online reviews'
        ],
        'benefits': [
            'Dominate local search results',
            'Get more foot traffic',
            'Build strong online reputation',
            'Compete with big businesses'
        ],
        'keywords': ['local SEO', 'Google My Business', 'local customers', 'community']
    },
    'crypto': {
        'pain_points': [
            'Confused by complex crypto markets',
            'Missing profitable opportunities',
            'Losing money on bad trades',
            'Don\'t know which coins to buy'
        ],
        'benefits': [
            'Identify winning crypto projects',
            'Minimize trading risks',
            'Maximize profit potential',
            'Stay informed on market trends'
        ],
        'keywords': ['cryptocurrency', 'Bitcoin', 'DeFi', 'trading', 'blockchain']
    },
    'side-hustles': {
        'pain_points': [
            'Not earning enough from 9-5',
            'No time for extra income',
            'Don\'t know where to start',
            'Tried everything without success'
        ],
        'benefits': [
            'Create multiple income streams',
            'Work on your own schedule',
            'Build financial freedom',
            'Replace your day job income'
        ],
        'keywords': ['side hustle', 'passive income', 'financial freedom', 'extra money']
    }
}

# Advanced Prompt Functions
def get_niche_context(niche):
    """Get niche-specific context for better prompt customization"""
    return NICHE_CONTENT_PROMPTS.get(niche, {
        'pain_points': ['Common industry challenges'],
        'benefits': ['Generic benefits'],
        'keywords': ['general', 'business', 'success']
    })

def customize_prompt_for_niche(base_prompt, niche, **kwargs):
    """Customize a base prompt with niche-specific context"""
    niche_context = get_niche_context(niche)
    
    enhanced_prompt = base_prompt + f"""

NICHE-SPECIFIC CONTEXT:
Target Audience Pain Points: {', '.join(niche_context['pain_points'])}
Key Benefits to Highlight: {', '.join(niche_context['benefits'])}
Important Keywords: {', '.join(niche_context['keywords'])}

Use this context to make the content more relevant and targeted to the {niche} audience.
"""
    
    return enhanced_prompt.format(niche=niche, **kwargs)

# Urgency and Scarcity Templates
URGENCY_TEMPLATES = {
    'low': [
        'Limited time offer',
        'Don\'t miss out',
        'Act now'
    ],
    'medium': [
        'Only 24 hours left',
        'Limited spots available',
        'Price goes up soon'
    ],
    'high': [
        'URGENT: Deadline approaching',
        'Last chance to save',
        'Only 3 spots remaining'
    ],
    'extreme': [
        'FINAL WARNING: Offer expires in hours',
        'This is your last chance',
        'Doors close forever at midnight'
    ]
}

SCARCITY_TEMPLATES = {
    'quantity': [
        'Only {number} spots left',
        'Limited to {number} people only',
        '{number} copies remaining'
    ],
    'time': [
        'Expires in {time}',
        'Available for {time} only',
        'Deadline: {time}'
    ],
    'exclusive': [
        'Exclusive invitation only',
        'Private access for select few',
        'VIP members only'
    ]
}

# Social Proof Templates
SOCIAL_PROOF_TEMPLATES = [
    'Join 10,000+ successful {niche} entrepreneurs',
    'Trusted by industry leaders',
    'Featured in top {niche} publications',
    '★★★★★ Rated by 500+ customers',
    'Used by Fortune 500 companies'
]

# Call-to-Action Templates
CTA_TEMPLATES = {
    'urgency': [
        'Get instant access now!',
        'Claim your spot before it\'s gone!',
        'Secure your copy today!',
        'Don\'t wait - start now!'
    ],
    'benefit': [
        'Transform your {niche} business',
        'Start your success story',
        'Unlock your potential',
        'Join the winners'
    ],
    'fear': [
        'Don\'t get left behind',
        'Stop struggling alone',
        'Don\'t miss this opportunity',
        'Avoid costly mistakes'
    ]
}

# OpenAI API Integration Helper
def format_openai_prompt(template, **kwargs):
    """Format a prompt template with variables for OpenAI API"""
    try:
        formatted_prompt = template.format(**kwargs)
        return {
            'model': 'gpt-3.5-turbo',
            'messages': [
                {
                    'role': 'system',
                    'content': 'You are an expert copywriter and marketing strategist. Always respond with valid JSON format when requested.'
                },
                {
                    'role': 'user',
                    'content': formatted_prompt
                }
            ],
            'max_tokens': 1500,
            'temperature': 0.7
        }
    except KeyError as e:
        print(f"Missing variable in prompt: {e}")
        return None

# Example usage functions
def generate_profit_page_prompt(niche, offer_link, offer_description=""):
    """Generate a formatted prompt for profit page creation"""
    return format_openai_prompt(
        PROFIT_PAGE_PROMPT,
        niche=niche,
        offer_link=offer_link,
        offer_description=offer_description or f"Premium {niche} solution"
    )

def generate_email_sequence_prompt(niche, offer_description, offer_link):
    """Generate a formatted prompt for email sequence creation"""
    return format_openai_prompt(
        FOLLOW_UP_EMAIL_PROMPT,
        niche=niche,
        offer_description=offer_description,
        offer_link=offer_link
    )

def generate_social_content_prompt(niche, offer, platform="all", **options):
    """Generate a formatted prompt for social media content"""
    return format_openai_prompt(
        SOCIAL_POST_PROMPT,
        niche=niche,
        offer=offer,
        platform=platform,
        use_emojis=options.get('use_emojis', True),
        add_hooks=options.get('add_hooks', True)
    )