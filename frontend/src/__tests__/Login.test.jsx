import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, expect, test, vi } from 'vitest';
import Login from '../components/Login/Login';

beforeEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
  window.alert = vi.fn();
});

const renderLogin = () => render(<MemoryRouter><Login /></MemoryRouter>);

test('renders login form', () => {
  renderLogin();
  expect(screen.getByText('VulnChecker')).toBeInTheDocument();
  expect(screen.getByText('Gestión de Vulnerabilidades Wazuh')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /ingresar/i })).toBeInTheDocument();
});

test('shows loading state on submit', async () => {
  vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})));
  renderLogin();
  fireEvent.change(screen.getByLabelText('Correo electrónico institucional'), { target: { value: 'test.user' } });
  fireEvent.change(screen.getByLabelText('Contraseña'), { target: { value: 'mypass' } });
  fireEvent.submit(screen.getByRole('button', { name: /ingresar/i }).closest('form'));
  await waitFor(() => {
    expect(screen.getByText(/Verificando/i)).toBeInTheDocument();
  });
});

test('shows alert on 401 error', async () => {
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.resolve({ ok: false, status: 401, json: () => Promise.resolve({}) })
  ));
  renderLogin();
  fireEvent.change(screen.getByLabelText('Correo electrónico institucional'), { target: { value: 'test.user' } });
  fireEvent.change(screen.getByLabelText('Contraseña'), { target: { value: 'wrong' } });
  fireEvent.submit(screen.getByRole('button', { name: /ingresar/i }).closest('form'));
  await waitFor(() => {
    expect(window.alert).toHaveBeenCalledWith('Credenciales incorrectas o cuenta aún no aprobada por el administrador.');
  });
});

test('shows alert on server error (non-401)', async () => {
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({}) })
  ));
  renderLogin();
  fireEvent.change(screen.getByLabelText('Correo electrónico institucional'), { target: { value: 'test.user' } });
  fireEvent.change(screen.getByLabelText('Contraseña'), { target: { value: 'mypass' } });
  fireEvent.submit(screen.getByRole('button', { name: /ingresar/i }).closest('form'));
  await waitFor(() => {
    expect(window.alert).toHaveBeenCalledWith('Error en el servidor. Intente más tarde.');
  });
});

test('shows alert on network error', async () => {
  vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('Network error'))));
  renderLogin();
  fireEvent.change(screen.getByLabelText('Correo electrónico institucional'), { target: { value: 'test.user' } });
  fireEvent.change(screen.getByLabelText('Contraseña'), { target: { value: 'mypass' } });
  fireEvent.submit(screen.getByRole('button', { name: /ingresar/i }).closest('form'));
  await waitFor(() => {
    expect(window.alert).toHaveBeenCalledWith('No se pudo conectar con el servidor. Revise su conexión.');
  });
});

test('navigates to /home on successful admin login', async () => {
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.resolve({ ok: true, json: () => Promise.resolve({ id: 1, role: 'ADMIN', firstName: 'Carlos' }) })
  ));
  renderLogin();
  fireEvent.change(screen.getByLabelText('Correo electrónico institucional'), { target: { value: 'admin.user' } });
  fireEvent.change(screen.getByLabelText('Contraseña'), { target: { value: 'adminpass' } });
  fireEvent.submit(screen.getByRole('button', { name: /ingresar/i }).closest('form'));
  await waitFor(() => {
    expect(localStorage.getItem('is_authenticated')).toBe('true');
    expect(localStorage.getItem('user_role')).toBe('ADMIN');
  });
});

test('toggles password visibility', () => {
  renderLogin();
  const toggleBtn = document.querySelector('.toggle-password-btn');
  expect(toggleBtn).not.toBeNull();
  fireEvent.click(toggleBtn);
});

test('renders register link', () => {
  renderLogin();
  expect(screen.getByText(/Solicita acceso aquí/i)).toBeInTheDocument();
});

test('renders email domain', () => {
  renderLogin();
  expect(screen.getByText('@usach.cl')).toBeInTheDocument();
});

test('navigates to /home on successful user login', async () => {
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.resolve({ ok: true, json: () => Promise.resolve({ id: 2, role: 'USER', firstName: 'Juan' }) })
  ));
  renderLogin();
  fireEvent.change(screen.getByLabelText('Correo electrónico institucional'), { target: { value: 'user.test' } });
  fireEvent.change(screen.getByLabelText('Contraseña'), { target: { value: 'userpass' } });
  fireEvent.submit(screen.getByRole('button', { name: /ingresar/i }).closest('form'));
  await waitFor(() => {
    expect(localStorage.getItem('user_role')).toBe('USER');
  });
});
