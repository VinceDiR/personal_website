/**
 * Site behaviour: sticky header, scroll-spy nav, mobile menu, typed hero
 * subtitle, and the contact form submit. Adapted from the DevFolio template
 * by BootstrapMade (https://bootstrapmade.com/license/).
 */
(() => {
  "use strict";

  const $ = (selector, all = false) =>
    all ? [...document.querySelectorAll(selector)] : document.querySelector(selector);

  const header = $("#header");
  const navbar = $("#navbar");
  const navToggle = $(".mobile-nav-toggle");
  const backToTop = $(".back-to-top");
  const navLinks = $("#navbar .scrollto", true);

  /* Header state, back-to-top button, and active nav link follow the scroll position. */
  const onScroll = () => {
    const y = window.scrollY;
    header.classList.toggle("header-scrolled", y > 100);
    backToTop.classList.toggle("active", y > 100);

    const probe = y + 200;
    navLinks.forEach((link) => {
      const section = link.hash && document.querySelector(link.hash);
      if (!section) return;
      const inView = probe >= section.offsetTop && probe <= section.offsetTop + section.offsetHeight;
      link.classList.toggle("active", inView);
    });
  };
  window.addEventListener("scroll", onScroll, { passive: true });
  window.addEventListener("load", onScroll);

  /* Smooth scroll that leaves room for the fixed header. */
  const scrollTo = (hash) => {
    const target = document.querySelector(hash);
    if (!target) return;
    let offset = header.offsetHeight;
    if (!header.classList.contains("header-scrolled")) offset -= 16;
    window.scrollTo({ top: target.offsetTop - offset, behavior: "smooth" });
  };

  const setMobileNav = (open) => {
    navbar.classList.toggle("navbar-mobile", open);
    navToggle.classList.toggle("bi-list", !open);
    navToggle.classList.toggle("bi-x", open);
    navToggle.setAttribute("aria-expanded", String(open));
  };
  navToggle.addEventListener("click", () => {
    setMobileNav(!navbar.classList.contains("navbar-mobile"));
  });

  $(".scrollto", true).forEach((link) => {
    link.addEventListener("click", (event) => {
      if (!link.hash || !document.querySelector(link.hash)) return;
      event.preventDefault();
      setMobileNav(false);
      scrollTo(link.hash);
    });
  });

  window.addEventListener("load", () => {
    if (window.location.hash && document.querySelector(window.location.hash)) {
      scrollTo(window.location.hash);
    }
  });

  /* Hero subtitle typing effect. */
  const typed = $(".typed");
  if (typed && typeof Typed !== "undefined") {
    new Typed(".typed", {
      strings: typed.dataset.typedItems.split(",").map((s) => s.trim()),
      loop: true,
      typeSpeed: 100,
      backSpeed: 50,
      backDelay: 2000,
    });
  }

  /* Contact form: post as JSON-returning fetch so the page never reloads. */
  const form = $("#contact-form");
  if (form) {
    const loading = form.querySelector(".loading");
    const errorBox = form.querySelector(".error-message");
    const sentBox = form.querySelector(".sent-message");
    const submitButton = form.querySelector("button[type=submit]");

    const showError = (text) => {
      errorBox.textContent = text;
      errorBox.classList.add("d-block");
    };

    const postForm = async () => {
      // The render-time token lives on the form element, not in an input, so
      // only a client that executed this script can send it.
      const body = new FormData(form);
      if (!form.dataset.ft) console.warn("contact form token missing");
      body.set("ft", form.dataset.ft || "");
      const response = await fetch(form.action, {
        method: "POST",
        body,
        headers: { Accept: "application/json" },
      });
      return response.json().catch(() => ({ ok: false }));
    };

    const refreshToken = async () => {
      const response = await fetch("/form-token", { headers: { Accept: "application/json" } });
      const data = await response.json().catch(() => ({}));
      if (data.token) form.dataset.ft = data.token;
    };

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      errorBox.classList.remove("d-block");
      sentBox.classList.remove("d-block");

      if (typeof grecaptcha === "undefined" || !grecaptcha.getResponse()) {
        showError("Please complete the reCAPTCHA.");
        return;
      }

      loading.classList.add("d-block");
      submitButton.disabled = true;
      try {
        let data = await postForm();
        if (data.code === "ft-expired") {
          // The page sat open past the token lifetime. Fetch a new token and retry
          // once, instead of making the visitor reload and retype the message. The
          // reCAPTCHA answer is still unspent: that gate runs after the token gate.
          await refreshToken();
          data = await postForm();
        }
        if (!data.ok) {
          throw new Error(data.error || "Something went wrong. Please try again later.");
        }
        sentBox.textContent = data.message;
        sentBox.classList.add("d-block");
        form.reset();
      } catch (error) {
        showError(error.message);
      } finally {
        loading.classList.remove("d-block");
        submitButton.disabled = false;
        // A solved reCAPTCHA is single-use, so clear it on every outcome; retrying
        // with a spent token fails verification and looks like an attack.
        if (typeof grecaptcha !== "undefined") grecaptcha.reset();
      }
    });
  }
})();
