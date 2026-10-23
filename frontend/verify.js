    import { el, api, badge, fmtDate, fmtDay, rowHeader, titleCase, empty }
      from '/static/assets/core.js';

    const content = document.getElementById('content');

    /* The verification code alphabet (base32: A-Z and 2-7, with dashes), checked here so a
     * mistyped code gets a plain answer instead of the API's validation message. */
    const CODE_FORMAT = /^[A-Z2-7-]{16,40}$/;
    const NOT_FOUND_TITLE = 'We couldn\'t find that code';
    const NOT_FOUND_TEXT = 'Check it and try again. The code is printed under the QR code on '
      + 'the package. If you bought this product and the code still is not found, contact the '
      + 'retailer.';

    function normalise(code) {
      // Spaces are how people copy a code off a label; the code itself has none.
      return String(code || '').trim().toUpperCase().replace(/\s+/g, '');
    }

    /* Where the product is in its journey, in a shopper's words rather than the system's. */
    const STATE_WORDS = {
      CREATED: ['Registered', 'The batch has been recorded but has not moved yet.'],
      HARVESTED: ['Harvested', 'Picked at the farm and not yet processed.'],
      PROCESSED: ['Processed', 'Cleaned, milled or otherwise prepared after harvest.'],
      PACKAGED: ['Packed', 'Packed and ready to ship.'],
      IN_TRANSIT: ['On its way', 'Being transported to the next business in the chain.'],
      RECEIVED: ['Delivered', 'Received by the next business in the chain.'],
      STORED: ['In storage', 'Held in a warehouse before sale.'],
      RETAILED: ['On sale', 'Reached the shop.'],
      RECALLED: ['Recalled', 'This batch has been recalled. Do not eat it; follow the '
        + 'retailer\'s instructions.'],
    };

    function stateCell(state) {
      const [label, meaning] = STATE_WORDS[state] || [titleCase(state), ''];
      return el('td', {}, [
        el('span', { class: state === 'RECALLED' ? 'badge critical' : 'badge neutral',
          text: label }),
        meaning ? el('div', { class: 'hint', text: meaning }) : null,
      ]);
    }

    function journeyList(journey) {
      return el('ul', { class: 'timeline' }, journey.map((stage) => el('li', {
        class: stage.verified ? '' : 'unverified',
      }, [
        el('strong', { text: stage.stage }),
        el('div', { class: 'when', text: fmtDate(stage.occurred_at) }),
        stage.location ? el('div', { class: 'hint', text: stage.location }) : null,
        el('div', { class: 'u-mt-4' }, [stage.verified
          ? badge('VERIFIED')
          : el('span', { class: 'badge warning', text: 'Not confirmed on the ledger' })]),
      ])));
    }

    function certList(certifications) {
      if (!certifications.length) {
        return el('p', { class: 'hint', text: 'No certifications are claimed on this product.' });
      }
      return el('ul', { class: 'reasons' }, certifications.map((cert) => el('li', {
        class: cert.authentic ? 'good' : 'bad',
      }, [
        el('strong', { text: `${titleCase(cert.type)} (${cert.standard})` }),
        ' — ', cert.authentic ? 'valid' : 'could not be authenticated',
        ` (${String(cert.status).toLowerCase()}, valid until ${fmtDay(cert.valid_to)})`,
      ])));
    }

    function notFound() {
      return empty(NOT_FOUND_TITLE, NOT_FOUND_TEXT);
    }

    async function showResult(rawCode) {
      const code = normalise(rawCode);
      if (!CODE_FORMAT.test(code)) {
        content.replaceChildren(notFound());
        return;
      }
      content.replaceChildren(el('div', { class: 'loading', 'aria-busy': 'true' }, 'Verifying…'));
      try {
        const result = await api(`/verify/${encodeURIComponent(code)}`);
        content.replaceChildren(
          el('div', { class: 'status-line' }, [
            result.ledger_verified ? badge('VERIFIED') : badge('WARNING'),
            el('span', { class: 'hint',
              text: result.ledger_verified
                ? 'This product\'s record matches the tamper-evident ledger'
                : 'Part of this product\'s record could not be confirmed on the ledger' }),
          ]),
          el('div', { class: 'card' }, [
            el('h2', { text: result.product_name }),
            el('p', { class: 'hint', text: result.product_category }),
            el('table', {}, [
              el('tr', {}, [rowHeader('Origin'),
                el('td', { text: result.origin_region
                  ? `${result.origin_region}, ${result.origin_country}` : 'Not disclosed' })]),
              // A calendar day: no time of day was ever recorded for a harvest.
              el('tr', {}, [rowHeader('Harvested'),
                el('td', { text: fmtDay(result.harvested_at) })]),
              el('tr', {}, [rowHeader('GMO status'), el('td', {}, [
                badge(result.gmo_status),
                result.gmo_event_code
                  ? el('span', { class: 'hint mono',
                    text: ` (event ${result.gmo_event_code})` }) : null,
              ])]),
              el('tr', {}, [rowHeader('Where it is now'), stateCell(result.batch_state)]),
            ]),
          ]),
          el('div', { class: 'card' }, [
            el('h2', { text: 'Certifications' }),
            certList(result.certifications),
          ]),
          el('div', { class: 'card' }, [
            el('h2', { text: 'Journey' }),
            result.journey.length ? journeyList(result.journey)
              : empty('No journey recorded', 'No steps have been recorded for this batch yet.'),
          ]),
          el('p', { class: 'hint u-text-center', text: result.disclaimer }),
        );
      } catch (error) {
        // An unknown code (404) and a malformed one the server refused (400/422) mean the
        // same thing to a shopper. Nothing technical (validation text, request ids) is shown.
        content.replaceChildren([400, 404, 422].includes(error.status)
          ? notFound()
          : empty('We couldn\'t check this code right now',
            error.status === 429 ? 'Too many checks in a short time. Wait a minute and try again.'
              : 'Please try again in a few minutes.'));
      }
    }

    function showLookupForm() {
      const input = el('input', { placeholder: 'e.g. K7QF-2M9X-…', autofocus: 'autofocus',
        'aria-label': 'Verification code', autocapitalize: 'characters', spellcheck: 'false' });
      const form = el('form', { class: 'lookup-form' }, [
        input,
        el('button', { class: 'primary', type: 'submit', text: 'Verify' }),
      ]);
      const result = el('div', {}, [
        empty('Enter a verification code', 'Or scan the QR code printed on the package.')]);
      form.addEventListener('submit', (event) => {
        event.preventDefault();
        const code = normalise(input.value);
        if (!code) return;
        window.history.replaceState(null, '', `?code=${encodeURIComponent(code)}`);
        showResult(code).then(() => {
          // Keep the form above the answer so another code can be tried straight away.
          const answer = [...content.childNodes];
          result.replaceChildren(...answer);
          content.replaceChildren(form, result);
        });
      });
      content.replaceChildren(form, result);
    }

    const initial = new URLSearchParams(window.location.search).get('code') || '';
    if (initial) {
      const back = el('a', { href: '?', text: '← Look up a different code',
        class: 'u-block-mb-12' });
      showResult(initial).then(() => content.prepend(back));
    } else {
      showLookupForm();
    }
