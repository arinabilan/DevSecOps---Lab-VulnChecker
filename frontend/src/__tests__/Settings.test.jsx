import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, test, vi } from 'vitest';
import Settings from '../components/Settings/Settings';

const mockCredentials = [
  { id: 1, name: 'Prod-Server', sshUser: 'admin', wazuhUser: 'wazuh-admin' },
];

const mockPendingUsers = [
  { id: 1, firstName: 'Juan', paternalLastName: 'Perez', maternalLastName: 'Garcia', email: 'juan.perez@usach.cl' },
];

function createFetchMock(creds, users) {
  return vi.fn((url) => {
    if (url && url.includes('/pending')) return Promise.resolve({ ok: true, json: () => Promise.resolve(users || []) });
    if (url && url.includes('/infra-credentials')) return Promise.resolve({ ok: true, json: () => Promise.resolve(creds || []) });
    if (url && url.includes('/activate')) return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    if (url && url.includes('/users') && url.match(/\/users\/\d+$/)) return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
  });
}

function renderSettings() {
  return render(<MemoryRouter><Settings /></MemoryRouter>);
}

beforeEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
  window.alert = vi.fn();
  window.confirm = vi.fn(() => true);
});

test('renders section titles', async () => {
  localStorage.setItem('user_id', '1');
  localStorage.setItem('user_role', 'ADMIN');
  vi.stubGlobal('fetch', createFetchMock(mockCredentials, mockPendingUsers));
  renderSettings();
  expect(await screen.findByText(/Llavero de Credenciales/i)).toBeInTheDocument();
});

test('loads and displays credentials', async () => {
  localStorage.setItem('user_id', '1');
  localStorage.setItem('user_role', 'ADMIN');
  vi.stubGlobal('fetch', createFetchMock(mockCredentials, mockPendingUsers));
  renderSettings();
  expect(await screen.findByText('Prod-Server')).toBeInTheDocument();
  expect(screen.getByText('admin / wazuh-admin')).toBeInTheDocument();
});

test('loads pending users for admin', async () => {
  localStorage.setItem('user_id', '1');
  localStorage.setItem('user_role', 'ADMIN');
  vi.stubGlobal('fetch', createFetchMock(mockCredentials, mockPendingUsers));
  renderSettings();
  expect(await screen.findByText('Juan Perez Garcia')).toBeInTheDocument();
});

test('shows empty pending message', async () => {
  localStorage.setItem('user_id', '1');
  localStorage.setItem('user_role', 'ADMIN');
  vi.stubGlobal('fetch', createFetchMock([], []));
  renderSettings();
  expect(await screen.findByText(/No hay usuarios esperando aprobaci.n/i)).toBeInTheDocument();
});

test('does not show admin section for non-admin', async () => {
  localStorage.setItem('user_id', '1');
  localStorage.setItem('user_role', 'USER');
  vi.stubGlobal('fetch', createFetchMock(mockCredentials, []));
  renderSettings();
  expect(await screen.findByText('Prod-Server')).toBeInTheDocument();
  expect(screen.queryByText(/Aprobaci.n de Usuarios/i)).not.toBeInTheDocument();
});

test('opens verify modal on form submit', async () => {
  localStorage.setItem('user_id', '1');
  localStorage.setItem('user_role', 'USER');
  vi.stubGlobal('fetch', createFetchMock([], []));
  renderSettings();
  await screen.findByText(/Guardar Perfil/i);
  const form = document.querySelector('.credential-form');
  const inputs = form.querySelectorAll('input');
  fireEvent.change(inputs[0], { target: { value: 'Test' } });
  fireEvent.change(inputs[1], { target: { value: 'ssh' } });
  fireEvent.change(inputs[2], { target: { value: 'pass' } });
  fireEvent.change(inputs[3], { target: { value: 'wazuh' } });
  fireEvent.change(inputs[4], { target: { value: 'wazpass' } });
  fireEvent.submit(form);
  await waitFor(() => {
    expect(screen.getByText(/Verificaci.n de Seguridad/i)).toBeInTheDocument();
  });
});

test('saves when confirming modal', async () => {
  localStorage.setItem('user_id', '1');
  localStorage.setItem('user_role', 'USER');
  localStorage.setItem('auth_basic', 'dGVzdDp0ZXN0');
  const fetchMock = createFetchMock([], []);
  vi.stubGlobal('fetch', fetchMock);
  renderSettings();
  await screen.findByText(/Guardar Perfil/i);
  const form = document.querySelector('.credential-form');
  const inputs = form.querySelectorAll('input');
  fireEvent.change(inputs[0], { target: { value: 'Test' } });
  fireEvent.change(inputs[1], { target: { value: 'ssh' } });
  fireEvent.change(inputs[2], { target: { value: 'pass' } });
  fireEvent.change(inputs[3], { target: { value: 'wazuh' } });
  fireEvent.change(inputs[4], { target: { value: 'wazpass' } });
  fireEvent.submit(form);
  await screen.findByText(/Verificaci.n de Seguridad/i);
  fireEvent.submit(screen.getByRole('button', { name: /confirmar/i }).closest('form'));
  await waitFor(() => {
    const calls = fetchMock.mock.calls.filter(c => c[0] && c[0].includes('/infra-credentials'));
    expect(calls.length).toBeGreaterThanOrEqual(1);
  });
});

test('closing verify modal via X button', async () => {
  localStorage.setItem('user_id', '1');
  localStorage.setItem('user_role', 'USER');
  vi.stubGlobal('fetch', createFetchMock([], []));
  renderSettings();
  await screen.findByText(/Guardar Perfil/i);
  const form = document.querySelector('.credential-form');
  const inputs = form.querySelectorAll('input');
  fireEvent.change(inputs[0], { target: { value: 'Test' } });
  fireEvent.change(inputs[1], { target: { value: 'ssh' } });
  fireEvent.change(inputs[2], { target: { value: 'pass' } });
  fireEvent.change(inputs[3], { target: { value: 'wazuh' } });
  fireEvent.change(inputs[4], { target: { value: 'wazpass' } });
  fireEvent.submit(form);
  await screen.findByText(/Verificaci.n de Seguridad/i);
  const xBtn = document.querySelector('.close-modal-x');
  fireEvent.click(xBtn);
  expect(screen.queryByText(/Verificaci.n de Seguridad/i)).not.toBeInTheDocument();
});

test('canceling verify modal', async () => {
  localStorage.setItem('user_id', '1');
  localStorage.setItem('user_role', 'USER');
  vi.stubGlobal('fetch', createFetchMock([], []));
  renderSettings();
  await screen.findByText(/Guardar Perfil/i);
  const form = document.querySelector('.credential-form');
  const inputs = form.querySelectorAll('input');
  fireEvent.change(inputs[0], { target: { value: 'Test' } });
  fireEvent.change(inputs[1], { target: { value: 'ssh' } });
  fireEvent.change(inputs[2], { target: { value: 'pass' } });
  fireEvent.change(inputs[3], { target: { value: 'wazuh' } });
  fireEvent.change(inputs[4], { target: { value: 'wazpass' } });
  fireEvent.submit(form);
  await screen.findByText(/Verificaci.n de Seguridad/i);
  fireEvent.click(screen.getByText(/Cancelar/i));
  expect(screen.queryByText(/Verificaci.n de Seguridad/i)).not.toBeInTheDocument();
});

test('activate user on admin approve', async () => {
  localStorage.setItem('user_id', '1');
  localStorage.setItem('user_role', 'ADMIN');
  const fetchMock = createFetchMock(mockCredentials, mockPendingUsers);
  vi.stubGlobal('fetch', fetchMock);
  renderSettings();
  await screen.findByText('Juan Perez Garcia');
  fireEvent.click(screen.getByTitle(/Activar Usuario/i));
  await waitFor(() => {
    const calls = fetchMock.mock.calls.filter(c => c[0] && c[0].includes('/activate'));
    expect(calls.length).toBeGreaterThanOrEqual(1);
  });
});

test('reject user on admin delete', async () => {
  localStorage.setItem('user_id', '1');
  localStorage.setItem('user_role', 'ADMIN');
  const fetchMock = createFetchMock(mockCredentials, mockPendingUsers);
  vi.stubGlobal('fetch', fetchMock);
  renderSettings();
  await screen.findByText('Juan Perez Garcia');
  fireEvent.click(screen.getByTitle(/Rechazar/i));
  await waitFor(() => {
    const calls = fetchMock.mock.calls.filter(c => c[0] && c[1] && c[1].method === 'DELETE');
    expect(calls.length).toBeGreaterThanOrEqual(1);
  });
});

test('editing mode shows edit title', async () => {
  localStorage.setItem('user_id', '1');
  localStorage.setItem('user_role', 'USER');
  vi.stubGlobal('fetch', createFetchMock(mockCredentials, []));
  renderSettings();
  await screen.findByText('Prod-Server');
  fireEvent.click(screen.getByText(/Editar/i));
  expect(screen.getByText(/Editando Perfil/i)).toBeInTheDocument();
});

test('cancel edit resets form', async () => {
  localStorage.setItem('user_id', '1');
  localStorage.setItem('user_role', 'USER');
  vi.stubGlobal('fetch', createFetchMock(mockCredentials, []));
  renderSettings();
  await screen.findByText('Prod-Server');
  fireEvent.click(screen.getByText(/Editar/i));
  expect(screen.getByText(/Editando Perfil/i)).toBeInTheDocument();
  fireEvent.click(screen.getByText(/Cancelar Edici.n/i));
  expect(screen.getByText(/Llavero de Credenciales/i)).toBeInTheDocument();
});

test('shows admin section for admin', async () => {
  localStorage.setItem('user_id', '1');
  localStorage.setItem('user_role', 'ADMIN');
  vi.stubGlobal('fetch', createFetchMock(mockCredentials, mockPendingUsers));
  renderSettings();
  expect(await screen.findByText(/Aprobaci.n de Usuarios/i)).toBeInTheDocument();
});
