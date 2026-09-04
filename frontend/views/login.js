import { el, api, session, toast } from '/static/assets/core.js';

const DEMO_ACCOUNTS = [
  ['admin@absp.demo', 'Administrator'],
  ['farmer@absp.demo', 'Farm operator'],
  ['agronomist@absp.demo', 'Agronomist'],
  ['analyst@absp.demo', 'Security analyst'],
  ['researcher@absp.demo', 'Biotech researcher'],
  ['biosafety@absp.demo', 'Biosafety officer'],
  ['supply@absp.demo', 'Supply chain operator'],
  ['certifier@absp.demo', 'Certifier'],
  ['regulator@absp.demo', 'Regulator'],
];
const DEMO_PASSWORD = 'DemoPassw0rd!2026';
// The administrator account is pre-selected because it is the only role whose navigation
// shows every area of the platform. Signing in without changing anything used to land on
// the farm operator's reduced view, which reads as "half the features are missing".
const DEFAULT_ACCOUNT = 'admin@absp.demo';

export async function render() {
  const emailInput = el('input', { type: 'email', id: 'email', required: 'required',
    autocomplete: 'username', value: DEFAULT_ACCOUNT });
  const passwordInput = el('input', { type: 'password', id: 'password', required: 'required',
    autocomplete: 'current-password', value: DEMO_PASSWORD });
  const errorNode = el('div', { class: 'error-text', role: 'alert', 'aria-live': 'polite' });
  const submit = el('button', { class: 'primary', type: 'submit', text: 'Sign in' });

  async function signIn(event) {
    event.preventDefault();
    errorNode.textContent = '';
    submit.disabled = true;
    submit.textContent = 'Signing in…';
    try {
      const tokens = await api('/auth/login', {
        method: 'POST',
        body: { email: emailInput.value.trim(), password: passwordInput.value },
      });
      session.write(tokens);
      const me = await api('/auth/me');
      session.write({ ...tokens, ...me });
      toast(`Signed in as ${me.full_name} (${me.role})`, 'ok');
      window.location.hash = '#/dashboard';
    } catch (error) {
      errorNode.textContent = error.status === 429
        ? `${error.message} The authentication rate limit is a security control.`
        : error.message;
      session.clear();
    } finally {
      submit.disabled = false;
      submit.textContent = 'Sign in';
    }
  }

  // Selecting an account only fills the form; the credentials are still posted to
  // /auth/login and verified by the server exactly as typed ones are.
  const accountButtons = DEMO_ACCOUNTS.map(([email, label]) => {
    const button = el('button', {
      type: 'button', text: label, title: email,
      'aria-pressed': email === DEFAULT_ACCOUNT ? 'true' : 'false',
      class: email === DEFAULT_ACCOUNT ? 'selected' : null,
      onClick: () => {
        emailInput.value = email;
        passwordInput.value = DEMO_PASSWORD;
        for (const other of accountButtons) {
          const chosen = other === button;
          other.classList.toggle('selected', chosen);
          other.setAttribute('aria-pressed', chosen ? 'true' : 'false');
        }
      },
    });
    return button;
  });

  return el('div', { class: 'centre' }, [
    el('div', { class: 'card login-card' }, [
      el('h1', { text: 'Agricultural Biotechnology Security Platform' }),
      el('p', { class: 'subtitle',
        text: 'Precision farming protection, GMO traceability and food supply chain security.' }),
      el('span', { class: 'demo-flag', text: 'DEMO / SIMULATION' }),
      el('form', { onSubmit: signIn, class: 'u-mt-16' }, [
        el('div', { class: 'field' }, [
          el('label', { for: 'email', text: 'Email address' }), emailInput,
        ]),
        el('div', { class: 'field' }, [
          el('label', { for: 'password', text: 'Password' }), passwordInput,
        ]),
        errorNode,
        el('div', { class: 'row u-mt-8' }, [
          submit,
          el('a', { href: '/verify.html', class: 'hint',
            text: 'Verify a product instead →' }),
        ]),
      ]),
      el('h3', { id: 'demo-accounts', text: 'Demonstration accounts' }),
      el('p', { class: 'credential-list',
        text: 'Choose a role to fill the form, then press Sign in. Each role sees a '
          + 'different part of the platform, so the navigation changes with the account. '
          + `Administrator is selected by default and sees every area. Every seeded `
          + `account uses the password ${DEMO_PASSWORD}, and these credentials exist only `
          + 'in the seeded demo database.' }),
      el('div', { class: 'row', role: 'group', 'aria-labelledby': 'demo-accounts' },
        accountButtons),
    ]),
  ]);
}
