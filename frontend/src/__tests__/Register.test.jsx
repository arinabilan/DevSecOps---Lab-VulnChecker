import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, test, vi } from 'vitest';
import Register from '../components/Login/Register';

beforeEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
  window.alert = vi.fn();
});

const renderRegister = () => render(
  <MemoryRouter>
    <Register />
  </MemoryRouter>
);

test('renders registration form with all fields', () => {
  renderRegister();
  expect(screen.getByText('Registro')).toBeInTheDocument();
  expect(screen.getByText('Solicita acceso al sistema VulnChecker')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /solicitar acceso/i })).toBeInTheDocument();
});

test('shows alert when passwords do not match', async () => {
  renderRegister();
  fireEvent.change(screen.getByLabelText('Contraseña'), { target: { value: 'pass1' } });
  fireEvent.change(screen.getByLabelText('Confirmar Contraseña'), { target: { value: 'pass2' } });
  fireEvent.submit(screen.getByRole('button', { name: /solicitar acceso/i }).closest('form'));
  await waitFor(() => {
    expect(window.alert).toHaveBeenCalledWith('Las contraseñas no coinciden');
  });
});

test('shows loading state on submit', async () => {
  vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})));
  renderRegister();
  fireEvent.change(screen.getByLabelText('Nombre'), { target: { value: 'Juan' } });
  fireEvent.change(screen.getByLabelText('Apellido Paterno'), { target: { value: 'Perez' } });
  fireEvent.change(screen.getByLabelText('Apellido Materno'), { target: { value: 'Garcia' } });
  fireEvent.change(screen.getByLabelText('Correo Institucional'), { target: { value: 'juan.perez' } });
  fireEvent.change(screen.getByLabelText('Contraseña'), { target: { value: 'pass123' } });
  fireEvent.change(screen.getByLabelText('Confirmar Contraseña'), { target: { value: 'pass123' } });
  fireEvent.submit(screen.getByRole('button', { name: /solicitar acceso/i }).closest('form'));
  await waitFor(() => {
    expect(screen.getByText(/Enviando solicitud/i)).toBeInTheDocument();
  });
});

test('shows success alert on successful registration', async () => {
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.resolve({ ok: true, json: () => Promise.resolve({}) })
  ));
  renderRegister();
  fireEvent.change(screen.getByLabelText('Nombre'), { target: { value: 'Juan' } });
  fireEvent.change(screen.getByLabelText('Apellido Paterno'), { target: { value: 'Perez' } });
  fireEvent.change(screen.getByLabelText('Apellido Materno'), { target: { value: 'Garcia' } });
  fireEvent.change(screen.getByLabelText('Correo Institucional'), { target: { value: 'juan.perez' } });
  fireEvent.change(screen.getByLabelText('Contraseña'), { target: { value: 'pass123' } });
  fireEvent.change(screen.getByLabelText('Confirmar Contraseña'), { target: { value: 'pass123' } });
  fireEvent.submit(screen.getByRole('button', { name: /solicitar acceso/i }).closest('form'));
  await waitFor(() => {
    expect(window.alert).toHaveBeenCalledWith(
      expect.stringContaining('Solicitud enviada con éxito')
    );
  });
});

test('shows error alert on 409', async () => {
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.resolve({ ok: false, status: 409, json: () => Promise.resolve({ message: 'Email en uso' }) })
  ));
  renderRegister();
  fireEvent.change(screen.getByLabelText('Nombre'), { target: { value: 'Juan' } });
  fireEvent.change(screen.getByLabelText('Apellido Paterno'), { target: { value: 'Perez' } });
  fireEvent.change(screen.getByLabelText('Apellido Materno'), { target: { value: 'Garcia' } });
  fireEvent.change(screen.getByLabelText('Correo Institucional'), { target: { value: 'juan.perez' } });
  fireEvent.change(screen.getByLabelText('Contraseña'), { target: { value: 'pass123' } });
  fireEvent.change(screen.getByLabelText('Confirmar Contraseña'), { target: { value: 'pass123' } });
  fireEvent.submit(screen.getByRole('button', { name: /solicitar acceso/i }).closest('form'));
  await waitFor(() => {
    expect(window.alert).toHaveBeenCalledWith('Email en uso');
  });
});

test('shows generic error on failed fetch without message', async () => {
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({}) })
  ));
  renderRegister();
  fireEvent.change(screen.getByLabelText('Nombre'), { target: { value: 'Juan' } });
  fireEvent.change(screen.getByLabelText('Apellido Paterno'), { target: { value: 'Perez' } });
  fireEvent.change(screen.getByLabelText('Apellido Materno'), { target: { value: 'Garcia' } });
  fireEvent.change(screen.getByLabelText('Correo Institucional'), { target: { value: 'juan.perez' } });
  fireEvent.change(screen.getByLabelText('Contraseña'), { target: { value: 'pass123' } });
  fireEvent.change(screen.getByLabelText('Confirmar Contraseña'), { target: { value: 'pass123' } });
  fireEvent.submit(screen.getByRole('button', { name: /solicitar acceso/i }).closest('form'));
  await waitFor(() => {
    expect(window.alert).toHaveBeenCalledWith(
      expect.stringContaining('Error al registrar')
    );
  });
});

test('shows connection error on network failure', async () => {
  vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('Network error'))));
  renderRegister();
  fireEvent.change(screen.getByLabelText('Nombre'), { target: { value: 'Juan' } });
  fireEvent.change(screen.getByLabelText('Apellido Paterno'), { target: { value: 'Perez' } });
  fireEvent.change(screen.getByLabelText('Apellido Materno'), { target: { value: 'Garcia' } });
  fireEvent.change(screen.getByLabelText('Correo Institucional'), { target: { value: 'juan.perez' } });
  fireEvent.change(screen.getByLabelText('Contraseña'), { target: { value: 'pass123' } });
  fireEvent.change(screen.getByLabelText('Confirmar Contraseña'), { target: { value: 'pass123' } });
  fireEvent.submit(screen.getByRole('button', { name: /solicitar acceso/i }).closest('form'));
  await waitFor(() => {
    expect(window.alert).toHaveBeenCalledWith(
      expect.stringContaining('No se pudo conectar')
    );
  });
});
