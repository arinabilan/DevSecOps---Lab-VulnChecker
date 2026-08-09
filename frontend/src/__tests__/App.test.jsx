import { render, screen } from '@testing-library/react';
import { beforeEach, expect, test, vi } from 'vitest';
import App from '../App';

beforeEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
});

test('renders Login page at root path', () => {
  window.history.pushState({}, '', '/');
  render(<App />);
  expect(screen.getByText('Gestión de Vulnerabilidades Wazuh')).toBeInTheDocument();
});

test('renders Register page at /register', () => {
  window.history.pushState({}, '', '/register');
  render(<App />);
  expect(screen.getByText('Registro')).toBeInTheDocument();
});

test('redirects unauthenticated user from /home to /', () => {
  window.history.pushState({}, '', '/home');
  render(<App />);
  expect(screen.getByText('Gestión de Vulnerabilidades Wazuh')).toBeInTheDocument();
});

test('renders Home for authenticated user', () => {
  localStorage.setItem('is_authenticated', 'true');
  localStorage.setItem('user_role', 'USER');
  window.history.pushState({}, '', '/home');
  render(<App />);
  expect(screen.getByText(/Panel de Gesti.n/i)).toBeInTheDocument();
});

test('redirects non-admin from /settings to /home', () => {
  localStorage.setItem('is_authenticated', 'true');
  localStorage.setItem('user_role', 'USER');
  window.history.pushState({}, '', '/settings');
  render(<App />);
  expect(screen.getByText(/Panel de Gesti.n/i)).toBeInTheDocument();
});

test('allows admin to access /settings', () => {
  localStorage.setItem('is_authenticated', 'true');
  localStorage.setItem('user_role', 'ADMIN');
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.resolve({ ok: true, json: () => Promise.resolve([]) })
  ));
  window.history.pushState({}, '', '/settings');
  render(<App />);
  expect(screen.getByText(/Llavero de Credenciales/i)).toBeInTheDocument();
});

test('wildcard route redirects to /', () => {
  window.history.pushState({}, '', '/nonexistent');
  render(<App />);
  expect(screen.getByText('Gestión de Vulnerabilidades Wazuh')).toBeInTheDocument();
});

test('renders Navbar on authenticated pages', () => {
  localStorage.setItem('is_authenticated', 'true');
  localStorage.setItem('user_role', 'USER');
  window.history.pushState({}, '', '/home');
  render(<App />);
  expect(screen.getByText(/VulnChecker/i)).toBeInTheDocument();
});

test('does not render Navbar on public pages - Login title shown', () => {
  window.history.pushState({}, '', '/');
  render(<App />);
  expect(screen.getByText('Gestión de Vulnerabilidades Wazuh')).toBeInTheDocument();
});
