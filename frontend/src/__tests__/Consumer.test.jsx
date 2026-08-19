import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, expect, test, vi } from 'vitest';
import Consumer from '../components/Consumer/Consumer';

const eventSourceInstances = [];
class MockEventSource {
  constructor(url) {
    this.url = url;
    this._listeners = {};
    eventSourceInstances.push(this);
  }
  addEventListener(event, handler) {
    this._listeners[event] = handler;
  }
  close() {}
  _dispatch(event, data) {
    if (this._listeners[event]) this._listeners[event](data);
  }
}

beforeEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
  globalThis.EventSource = MockEventSource;
  eventSourceInstances.length = 0;
});

const mockCredentials = [
  { id: 1, name: 'Cred-A', sshUser: 'admin', wazuhUser: 'wazuh' },
];

const renderConsumer = () => render(<MemoryRouter><Consumer /></MemoryRouter>);

function consumerFetchMock(behavior = 'success') {
  return vi.fn((url) => {
    if (url && url.includes('/infra-credentials')) {
      return Promise.resolve({ ok: true, json: () => Promise.resolve(mockCredentials) });
    }
    if (url && url.includes('/remote-new-count')) {
      if (behavior === 'no-new') return Promise.resolve({ ok: true, json: () => Promise.resolve({ newCount: 0 }) });
      if (behavior === 'count-fail') return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ newCount: 5 }) });
    }
    if (url && url.includes('/consume')) {
      if (behavior === 'already-synced') return Promise.resolve({ ok: true, json: () => Promise.resolve({ alreadySynced: true, message: 'Ya sincronizado' }) });
      if (behavior === 'fetch-error') return Promise.reject(new Error('Fetch error'));
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ taskId: 'task-123' }) });
    }
    return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
  });
}

test('renders consumer title', () => {
  localStorage.setItem('user_id', '1');
  renderConsumer();
  expect(screen.getByText(/Configuraci.n Wazuh/i)).toBeInTheDocument();
});

test('shows main subtitle', () => {
  localStorage.setItem('user_id', '1');
  renderConsumer();
  expect(screen.getByText(/Asocia tus servidores/i)).toBeInTheDocument();
});

test('renders default server row', () => {
  localStorage.setItem('user_id', '1');
  renderConsumer();
  expect(screen.getByText(/Direcci.n IP/i)).toBeInTheDocument();
});

test('adds a new server row', () => {
  localStorage.setItem('user_id', '1');
  renderConsumer();
  fireEvent.click(screen.getByText(/A.adir otro objetivo/i));
  expect(screen.getAllByPlaceholderText('192.168.1.XX').length).toBe(2);
});

test('removes a server row', () => {
  localStorage.setItem('user_id', '1');
  renderConsumer();
  fireEvent.click(screen.getByText(/A.adir otro objetivo/i));
  expect(screen.getAllByPlaceholderText('192.168.1.XX').length).toBe(2);
  const removeBtns = document.querySelectorAll('.remove-btn');
  fireEvent.click(removeBtns[1]);
  expect(screen.getAllByPlaceholderText('192.168.1.XX').length).toBe(1);
});

test('back button is rendered', () => {
  localStorage.setItem('user_id', '1');
  renderConsumer();
  const backBtn = document.querySelector('.back-button');
  expect(backBtn).not.toBeNull();
  fireEvent.click(backBtn);
});

test('loads credentials from API', async () => {
  localStorage.setItem('user_id', '1');
  vi.stubGlobal('fetch', consumerFetchMock());
  renderConsumer();
  expect(await screen.findByText('Cred-A')).toBeInTheDocument();
});

test('does not fetch credentials without userId', () => {
  vi.stubGlobal('fetch', consumerFetchMock());
  renderConsumer();
  expect(screen.getByText(/Configuraci.n Wazuh/i)).toBeInTheDocument();
});

test('form submit triggers consume API', async () => {
  localStorage.setItem('user_id', '1');
  localStorage.setItem('auth_basic', 'dGVzdDp0ZXN0');
  const fetchMock = consumerFetchMock();
  vi.stubGlobal('fetch', fetchMock);
  renderConsumer();
  await screen.findByText('Cred-A');
  const ipInput = screen.getByPlaceholderText('192.168.1.XX');
  fireEvent.change(ipInput, { target: { value: '10.0.0.1' } });
  const select = screen.getByRole('combobox');
  fireEvent.change(select, { target: { value: '1' } });
  fireEvent.submit(screen.getByText(/Iniciar Consumo de Datos/i).closest('form'));
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/consume'),
      expect.objectContaining({ method: 'POST' })
    );
  });
});

test('form submit with count-fail shows info notification', async () => {
  localStorage.setItem('user_id', '1');
  localStorage.setItem('auth_basic', 'dGVzdDp0ZXN0');
  const fetchMock = consumerFetchMock('count-fail');
  vi.stubGlobal('fetch', fetchMock);
  renderConsumer();
  await screen.findByText('Cred-A');
  fireEvent.submit(screen.getByText(/Iniciar Consumo de Datos/i).closest('form'));
  await waitFor(() => {
    expect(screen.getByText(/No hay nuevas vulnerabilidades/i)).toBeInTheDocument();
  });
});

test('form submit with no new vulns shows info notification', async () => {
  localStorage.setItem('user_id', '1');
  localStorage.setItem('auth_basic', 'dGVzdDp0ZXN0');
  const fetchMock = consumerFetchMock('no-new');
  vi.stubGlobal('fetch', fetchMock);
  renderConsumer();
  await screen.findByText('Cred-A');
  fireEvent.submit(screen.getByText(/Iniciar Consumo de Datos/i).closest('form'));
  await waitFor(() => {
    expect(screen.getByText(/No hay nuevas vulnerabilidades/i)).toBeInTheDocument();
  });
});

test('form submit with already synced', async () => {
  localStorage.setItem('user_id', '1');
  localStorage.setItem('auth_basic', 'dGVzdDp0ZXN0');
  vi.stubGlobal('fetch', consumerFetchMock('already-synced'));
  renderConsumer();
  await screen.findByText('Cred-A');
  fireEvent.submit(screen.getByText(/Iniciar Consumo de Datos/i).closest('form'));
  await waitFor(() => {
    expect(screen.getByText(/Ya sincronizado/i)).toBeInTheDocument();
  });
});

test('form submit fetch error shows notification', async () => {
  localStorage.setItem('user_id', '1');
  localStorage.setItem('auth_basic', 'dGVzdDp0ZXN0');
  vi.stubGlobal('fetch', consumerFetchMock('fetch-error'));
  renderConsumer();
  await screen.findByText('Cred-A');
  fireEvent.submit(screen.getByText(/Iniciar Consumo de Datos/i).closest('form'));
  await waitFor(() => {
    expect(screen.getByText(/Error al iniciar la sincronización/i)).toBeInTheDocument();
  });
});

test('SSE progress event updates counter', async () => {
  localStorage.setItem('user_id', '1');
  localStorage.setItem('auth_basic', 'dGVzdDp0ZXN0');
  vi.stubGlobal('fetch', consumerFetchMock());
  renderConsumer();
  await screen.findByText('Cred-A');
  fireEvent.submit(screen.getByText(/Iniciar Consumo de Datos/i).closest('form'));
  await waitFor(() => {
    expect(eventSourceInstances.length).toBeGreaterThan(0);
  });
  const es = eventSourceInstances[0];
  es._dispatch('progress', { data: JSON.stringify({ processed: 3, total: 10 }) });
  await waitFor(() => {
    expect(screen.getByText(/Recibidas 3 de 10 vulnerabilidades/i)).toBeInTheDocument();
  });
});

test('SSE complete event shows success notification', async () => {
  localStorage.setItem('user_id', '1');
  localStorage.setItem('auth_basic', 'dGVzdDp0ZXN0');
  vi.stubGlobal('fetch', consumerFetchMock());
  renderConsumer();
  await screen.findByText('Cred-A');
  fireEvent.submit(screen.getByText(/Iniciar Consumo de Datos/i).closest('form'));
  await waitFor(() => {
    expect(eventSourceInstances.length).toBeGreaterThan(0);
  });
  const es = eventSourceInstances[0];
  es._dispatch('complete', undefined);
  await waitFor(() => {
    expect(screen.getByText(/Sincronización completada/i)).toBeInTheDocument();
  });
});

test('SSE error event shows error notification', async () => {
  localStorage.setItem('user_id', '1');
  localStorage.setItem('auth_basic', 'dGVzdDp0ZXN0');
  vi.stubGlobal('fetch', consumerFetchMock());
  renderConsumer();
  await screen.findByText('Cred-A');
  fireEvent.submit(screen.getByText(/Iniciar Consumo de Datos/i).closest('form'));
  await waitFor(() => {
    expect(eventSourceInstances.length).toBeGreaterThan(0);
  });
  const es = eventSourceInstances[0];
  es._dispatch('error', undefined);
  await waitFor(() => {
    expect(screen.getByText(/Error en la sincronización/i)).toBeInTheDocument();
  });
});
