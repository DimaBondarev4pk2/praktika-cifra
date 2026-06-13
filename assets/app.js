const menuToggle = document.querySelector('.menu-toggle');
const topbarNav = document.querySelector('.topbar nav');
const themeOptions = document.querySelectorAll('[data-theme-value]');

function applyTheme(theme, shouldSave = true) {
  const nextTheme = theme === 'dark' ? 'dark' : 'light';
  document.documentElement.dataset.theme = nextTheme;

  themeOptions.forEach((button) => {
    const isActive = button.dataset.themeValue === nextTheme;
    button.classList.toggle('active', isActive);
    button.setAttribute('aria-pressed', String(isActive));
  });

  if (shouldSave) {
    localStorage.setItem('practice_theme', nextTheme);
  }
}

applyTheme(document.documentElement.dataset.theme || localStorage.getItem('practice_theme') || 'light', false);

themeOptions.forEach((button) => {
  button.addEventListener('click', () => {
    applyTheme(button.dataset.themeValue);
  });
});

function closeMenu() {
  topbarNav?.classList.remove('open');
  menuToggle?.setAttribute('aria-expanded', 'false');
}

menuToggle?.setAttribute('aria-expanded', 'false');
menuToggle?.addEventListener('click', () => {
  const isOpen = topbarNav?.classList.toggle('open') ?? false;
  menuToggle.setAttribute('aria-expanded', String(isOpen));
});

topbarNav?.querySelectorAll('a').forEach((link) => {
  link.addEventListener('click', closeMenu);
});

window.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') closeMenu();
});

window.addEventListener('resize', () => {
  if (window.innerWidth > 980) closeMenu();
});

document.querySelectorAll('input[type="file"]').forEach((input) => {
  input.addEventListener('change', () => {
    const label = input.closest('label');
    if (label && input.files?.[0]) label.firstChild.textContent = `Выбран файл: ${input.files[0].name} `;
  });
});

const cookieBanner = document.querySelector('[data-cookie-banner]');
const cookieAccept = document.querySelector('[data-cookie-accept]');

if (cookieBanner && localStorage.getItem('practice_cookie_accept') !== 'yes') {
  cookieBanner.hidden = false;
}

cookieAccept?.addEventListener('click', () => {
  localStorage.setItem('practice_cookie_accept', 'yes');
  if (cookieBanner) cookieBanner.hidden = true;
});
