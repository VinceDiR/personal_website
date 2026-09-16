"""Content scorer: legitimate mail must pass, textbook spam must flag."""

import spamcheck


def run(name, email, subject, message, **kwargs):
    return spamcheck.score(name, email, subject, message, **kwargs)


def hit_labels(verdict):
    return [h.split("(")[0] for h in verdict.hits]


def test_recruiter_with_linkedin_link_is_allowed():
    verdict = run(
        "Jane Doe",
        "jane.doe@bigcorp.com",
        "Senior Data Engineer opportunity",
        "Hi Vince, I'm a recruiter at BigCorp hiring for a data engineer role on our team. "
        "Your Airflow work looks relevant. Salary is $180k-$210k. "
        "Profile: https://www.linkedin.com/in/janedoe. Open to an interview?",
    )
    assert verdict.verdict == "allow"
    assert verdict.total <= 0
    assert "links:untrusted-url x1" not in hit_labels(verdict)
    assert verdict.url_count == 1


def test_short_colleague_message_is_allowed():
    verdict = run("Sam", "sam@example.com", "Hello", "Hey Vince, long time. Coffee next week?")
    assert verdict.verdict == "allow"


def test_reader_mentioning_github_project_is_allowed():
    verdict = run(
        "Priya",
        "priya@uni.edu",
        "Question about your Ukraine ETL post",
        "Loved the Medium article. I forked github.com/VinceDiR/ukraine_etl_project and had a "
        "question about the BigQuery schema.",
    )
    assert verdict.verdict == "allow"


def test_seo_pitch_flags_and_would_block():
    pitch = (
        "Hi, I noticed your website is not on the first page of Google. Our agency offers "
        "affordable seo services and link building. See http://cheapseo.xyz and "
        "http://bit.ly/seo-deal. Get back to me for a free quote."
    )
    verdict = run("Mike", "mike.seo.pro@gmail.com", "Rank on Google", pitch)
    assert verdict.verdict == "flag"
    assert verdict.would_block is True
    blocked = run("Mike", "mike.seo.pro@gmail.com", "Rank on Google", pitch, block_enabled=True)
    assert blocked.verdict == "block"


def test_vocabulary_alone_never_blocks():
    verdict = run(
        "Zq",
        "zq@example.com",
        "Offer",
        "guest post backlink casino crypto forex viagra escort make money click here act now",
        block_enabled=True,
    )
    assert verdict.total >= 12
    assert verdict.verdict == "flag"
    assert verdict.would_block is False


def test_disposable_email_and_strong_phrase():
    verdict = run("Bob", "bob@mailinator.com", "Hi", "We offer logo design and explainer videos.")
    assert "email:disposable-domain" in hit_labels(verdict)
    assert verdict.total >= 6


def test_cyrillic_message_scores_script_family():
    verdict = run(
        "Иван", "ivan@example.ru", "Предложение", "Здравствуйте, предлагаем услуги продвижения."
    )
    labels = hit_labels(verdict)
    assert any(label.startswith("script:non-latin") for label in labels)
    assert "email:bad-tld" in labels


def test_html_anchor_scores_markup():
    verdict = run("x", "x@example.com", "hi", 'Visit <a href="http://x.example">here</a> now')
    assert "markup:href" in hit_labels(verdict)


def test_name_with_url_scores_name_family():
    verdict = run("http://spam.example", "x@example.com", "hi", "hello there friend")
    assert "name:url-in-name" in hit_labels(verdict)


def test_email_addresses_in_body_are_not_links():
    verdict = run("Sam", "sam@example.com", "Contact", "Reach me at sam.smith@gmail.com anytime.")
    assert not any(label.startswith("links:") for label in hit_labels(verdict))


def test_duplicate_template_from_three_domains():
    body = (
        "Hello, we can build you a beautiful new site for a fixed price, "
        "check our portfolio at http://sites-r-us.example and reply for details."
    )
    run("A", "a@one.example", "Website", body)
    run("B", "b@two.example", "Website", body)
    third = run("C", "c@three.example", "Website", body)
    assert "dupe:same-body x3 senders" in hit_labels(third)


def test_colleagues_at_one_agency_are_not_a_duplicate():
    body = (
        "Hi Vince, sharing the same job description my colleague sent: senior data engineer, "
        "remote, working on Airflow pipelines. Happy to set up a call this week."
    )
    run("Ann", "ann@agency.example", "Role", body)
    run("Ben", "ben@agency.example", "Role", body)
    third = run("Cat", "cat@agency.example", "Role", body)
    assert not any(label.startswith("dupe:") for label in hit_labels(third))


def test_same_sender_resubmitting_is_not_a_duplicate():
    body = "Hi Vince, following up on my earlier note about the data platform role at our company."
    run("A", "a@example.com", "Follow up", body)
    again = run("A", "a@example.com", "Follow up", body)
    assert not any(label.startswith("dupe:") for label in hit_labels(again))


def test_extra_hits_count_toward_total():
    verdict = run(
        "Zq",
        "zq@example.com",
        "Hello",
        "Quick hello there.",
        extra_hits=[("captcha", "unverified", 6)],
    )
    assert "captcha:unverified(+6)" in verdict.hits
    assert verdict.total >= 6
    assert verdict.verdict == "flag"


def test_trust_is_floored():
    verdict = run(
        "Vince",
        "vince@example.com",
        "airflow bigquery python sql dbt spark",
        "recruiter role position interview resume linkedin github hiring job medium article",
    )
    assert verdict.total >= spamcheck.TRUST_FLOOR


# --- Evasions the scorer must not fall for ---------------------------------------------------


def test_at_sign_inside_a_url_still_scores_the_link():
    verdict = run(
        "Mike", "mike@example.com", "Hello", "Our portfolio is at http://x@cheapseo.xyz/offer here"
    )
    labels = hit_labels(verdict)
    assert "links:untrusted-url x1" in labels
    assert "links:bad-tld" in labels
    assert "links:userinfo-url" in labels
    assert verdict.url_count == 1


def test_userinfo_url_does_not_borrow_a_trusted_host():
    verdict = run(
        "Mike", "mike@example.com", "Hi", "Profile http://linkedin.com@cheapseo.xyz/ for you"
    )
    labels = hit_labels(verdict)
    assert "trust:trusted-link" not in labels
    assert "links:untrusted-url x1" in labels


def test_invisible_characters_do_not_hide_spam_phrases():
    # Soft hyphen, left-to-right mark and combining grapheme joiner inside the keywords.
    message = "We offer back­link and guest‎ post services and link͏ building " "for casi‏no sites"
    verdict = run("Mike", "mike@example.com", "Hello", message)
    labels = hit_labels(verdict)
    assert any(label.startswith("vocab:strong") for label in labels)
    assert "markup:invisible-chars" in labels
    assert verdict.verdict == "flag"


def test_emoji_and_persian_joiners_are_not_hidden_characters():
    emoji = run(
        "Sam", "sam@example.com", "Hello", "Hey Vince, loved the post \U0001f9d1‍\U0001f4bb"
    )
    persian = run("Ali", "ali@example.com", "Salam", "سلام، من مقاله شما را می‌خواهم بخوانم.")
    assert "markup:invisible-chars" not in hit_labels(emoji)
    assert "markup:invisible-chars" not in hit_labels(persian)


def test_bbcode_is_scored_not_dropped():
    verdict = run("x", "x@example.com", "hi", "[url=http://spam.example]click[/url]")
    assert "markup:bbcode" in hit_labels(verdict)
    assert verdict.verdict == "flag"


def test_markdown_link_and_bare_placeholder_are_not_bbcode():
    markdown = run(
        "Dana",
        "dana@bigcorp.com",
        "Data engineer role",
        "Hi Vince, here is [the JD](https://bigcorp.com/jobs/123). Keen to talk about the role?",
    )
    placeholder = run(
        "Dana",
        "dana@bigcorp.com",
        "Broken link",
        "I was reading your post and the [URL] in section two seems broken, thought you'd want it.",
    )
    assert "markup:bbcode" not in hit_labels(markdown)
    assert "markup:bbcode" not in hit_labels(placeholder)
    assert markdown.verdict == "allow" and placeholder.verdict == "allow"


def test_open_redirector_on_a_trusted_host_is_scored():
    verdict = run(
        "Ann",
        "ann@example.com",
        "Hi",
        "Watch https://youtube.com/redirect?q=http://cheapseo.xyz/deal for details",
    )
    labels = hit_labels(verdict)
    assert "links:redirector" in labels
    assert "trust:trusted-link" not in labels


def test_links_to_the_senders_own_domain_are_neutral():
    verdict = run(
        "Dana Price",
        "dana.price@brightreach.com",
        "Senior Data Engineer at BrightReach",
        "Hi Vince, I'm a recruiter at BrightReach, a digital marketing agency. We're hiring a "
        "data engineer for our lead generation platform. Role: "
        "https://brightreach.com/careers/data-engineer and our team page "
        "https://brightreach.com/about. Salary $180k-$200k. Open to an interview?",
    )
    assert "links:own-domain-url x2" in hit_labels(verdict)
    assert "links:untrusted-url x2" not in hit_labels(verdict)
    assert verdict.would_block is False
    assert verdict.verdict == "allow"


def test_small_startup_on_a_cheap_tld_is_not_flagged():
    verdict = run(
        "Priya",
        "info@datastack.site",
        "Consulting question",
        "Hi Vince, we're a small analytics startup. Read your Airflow post. Could we ask you "
        "about pipeline design? Our site is datastack.site",
    )
    assert verdict.verdict == "allow"


def test_non_latin_message_is_not_treated_as_empty():
    japanese = run(
        "Yuki",
        "yuki@example.jp",
        "こんにちは",
        "はじめまして。あなたのブログを読みました。データエンジニアリングについて質問があります。",
    )
    greek = run(
        "Nikos",
        "nikos@example.gr",
        "Γεια",
        "Καλημέρα, διάβασα το άρθρο σας για το Airflow και έχω μια ερώτηση σχετικά με τη ροή.",
    )
    for verdict in (japanese, greek):
        labels = hit_labels(verdict)
        assert "shape:very-short" not in labels
        assert "links:link-only" not in labels
        assert verdict.would_block is False


def test_non_latin_name_does_not_score_as_vowelless():
    verdict = run("Иванов", "ivanov@example.com", "Hello", "Hi Vince, a question about Airflow.")
    assert "name:no-vowel" not in hit_labels(verdict)


def test_missing_space_after_a_period_is_not_a_domain():
    verdict = run(
        "Sam",
        "sam@example.com",
        "Hello",
        "I read the post.Top marks for the Airflow section, it helped with our pipeline.",
    )
    assert not any(label.startswith("links:") for label in hit_labels(verdict))


def test_bare_domain_on_a_newer_tld_is_detected():
    verdict = run(
        "Ann", "ann@example.com", "Hi", "Our portfolio lives at cheapdesign.agency, take a look"
    )
    assert "links:untrusted-url x1" in hit_labels(verdict)


def test_pathological_input_is_fast():
    import time

    start = time.perf_counter()
    run("Sam", "sam@example.com", "hi", "a." * 2500)
    assert time.perf_counter() - start < 0.5


# Real sample: synonym-spun prose, so the payload only shows in the domain and path slugs.
_SPUN_PHARMA = (
    "Satgloxy",
    "vlajky@cialis-otc.com",
    "sarezgitakie aktermi mohair lefficacite",
    "The sisterhood arrived in less than 48 hours, well-packaged and just what I ordered. "
    "https://www.bandlab.com/apotekalmacom What really touched me was the minuscule "
    "handwritten note inside the package. https://www.ted.com/profiles/52136960 I've "
    "switched all my ancestors's habitual prescriptions to them. It's affordable and "
    "surprisingly human. https://www.fiverr.com/users/apotekalmacom66/lists/x-1976114904",
)


def test_spun_pharma_spam_on_reputable_hosts_would_block():
    verdict = run(*_SPUN_PHARMA)
    labels = hit_labels(verdict)
    assert "email:payload-domain:cialis" in labels
    # bandlab, ted and fiverr are reputable, so only the shared path slug gives them away.
    assert "links:payload-link:apotek" in labels
    assert verdict.would_block is True
    assert run(*_SPUN_PHARMA, block_enabled=True).verdict == "block"


def test_recruiter_at_a_pharmacy_chain_still_gets_through():
    """A payload word in a real employer's domain must not cost a legitimate sender."""
    verdict = run(
        "Karen Ruiz",
        "karen.ruiz@cvspharmacy.com",
        "Senior Data Engineer opening",
        "Hi Vince, I'm a technical recruiter at CVS. We're hiring a senior data engineer for "
        "our analytics platform team -- Airflow, BigQuery, dbt. Salary $185k-$215k. The JD is "
        "at https://cvspharmacy.com/careers/data-engineer. Open to a call this week?",
    )
    assert verdict.verdict == "allow"
    assert verdict.would_block is False


def test_a_gambling_employer_is_not_a_payload_word():
    """Betting firms hire data engineers, so gambling words stay out of PAYLOAD_WORDS."""
    verdict = run(
        "Dana",
        "dana@sportsbet-analytics.com",
        "Senior Data Engineer role",
        "Hi Vince, we run the data platform at a sports betting company and are hiring a "
        "senior data engineer for our Airflow stack. JD: https://sportsbet-analytics.com/jobs",
    )
    assert not any(label.startswith("email:payload-domain") for label in hit_labels(verdict))
    assert verdict.verdict == "allow"
