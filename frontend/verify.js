    import { el, clear, api, badge, fmtDate, rowHeader, titleCase, empty, errorBox }
      from '/static/assets/core.js';

    const content = document.getElementById('content');

    function codeFromUrl() {
      return new URLSearchParams(window.location.search).get('code') || '';
    }

    function journeyList(journey) {
      return el('ul', { class: 'timeline' }, journey.map((stage) => el('li', {
        class: stage.verified ? '' : 'unverified',
      }, [
        el('strong', { text: stage.stage }),
        el('div', { class: 'when', text: fmtDate(stage.occurred_at) }),
        stage.location ? el('div', { class: 'hint', text: stage.location }) : null,
        el('div', { class: 'u-mt-4' },
          [stage.verified ? badge('VERIFIED') : badge('WARNING')]),
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
        ` (status ${cert.status.toLowerCase()}, valid to ${fmtDate(cert.valid_to)})`,
      ])));
    }

    async function showResult(code) {
      content.replaceChildren(el('div', { class: 'loading', 'aria-busy': 'true' }, 'Verifying…'));
      try {
        const result = await api(`/verify/${encodeURIComponent(code)}`);
        content.replaceChildren(
          el('div', { class: 'status-line' }, [
            result.ledger_verified ? badge('VERIFIED') : badge('WARNING'),
            el('span', { class: 'hint',
              text: result.ledger_verified
                ? 'Verified against the blockchain ledger'
                : 'Could not be fully verified against the ledger' }),
          ]),
          el('div', { class: 'card' }, [
            el('h2', { text: result.product_name }),
            el('p', { class: 'hint', text: result.product_category }),
            el('table', {}, [
              el('tr', {}, [rowHeader('Origin'),
                el('td', { text: result.origin_region
                  ? `${result.origin_region}, ${result.origin_country}` : 'Not disclosed' })]),
              el('tr', {}, [rowHeader('Harvested'),
                el('td', { text: fmtDate(result.harvested_at) })]),
              el('tr', {}, [rowHeader('GMO status'), el('td', {}, [
                badge(result.gmo_status),
                result.gmo_event_code
                  ? el('span', { class: 'hint mono',
                    text: ` (event ${result.gmo_event_code})` }) : null,
              ])]),
              el('tr', {}, [rowHeader('Current state'),
                el('td', {}, [badge(result.batch_state)])]),
            ]),
          ]),
          el('div', { class: 'card' }, [
            el('h2', { text: 'Certifications' }),
            certList(result.certifications),
          ]),
          el('div', { class: 'card' }, [
            el('h2', { text: 'Journey' }),
            result.journey.length ? journeyList(result.journey)
              : empty('No journey recorded', 'No supply-chain events have been recorded yet.'),
          ]),
          el('p', { class: 'hint u-text-center', text: result.disclaimer }),
        );
      } catch (error) {
        content.replaceChildren(
          error.status === 404
            ? empty('Code not recognised', 'Check the code and try again. '
              + 'If this is a real purchase, contact the retailer.')
            : errorBox(error));
      }
    }

    function showLookupForm() {
      const input = el('input', { placeholder: 'e.g. K7QF-2M9X-…', autofocus: 'autofocus' });
      const form = el('form', { class: 'lookup-form' }, [
        input,
        el('button', { class: 'primary', type: 'submit', text: 'Verify' }),
      ]);
      form.addEventListener('submit', (event) => {
        event.preventDefault();
        const code = input.value.trim().toUpperCase();
        if (!code) return;
        window.history.replaceState(null, '', `?code=${encodeURIComponent(code)}`);
        showResult(code);
      });
      content.replaceChildren(
        form,
        empty('Enter a verification code', 'Or scan the QR code printed on the package.'));
    }

    const initial = codeFromUrl();
    if (initial) {
      const back = el('a', { href: '?', text: '← Look up a different code',
        class: 'u-block-mb-12' });
      showResult(initial).then(() => content.prepend(back));
    } else {
      showLookupForm();
    }
  