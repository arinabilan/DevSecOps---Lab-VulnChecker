import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, expect, test } from 'vitest';
import Home from '../components/Home/Home';

beforeEach(() => {
  localStorage.clear();
});

const renderHome = () => render(
  <MemoryRouter>
    <Home />
  </MemoryRouter>
);

test('renders welcome message with default user name', () => {
  renderHome();
  expect(screen.getByText(/¡Bienvenido, Usuario!/)).toBeInTheDocument();
});

test('renders welcome message with stored user name', () => {
  localStorage.setItem('user_name', 'Carlos');
  renderHome();
  expect(screen.getByText(/¡Bienvenido, Carlos!/)).toBeInTheDocument();
});

test('renders menu cards for USER role (no admin items)', () => {
  localStorage.setItem('user_role', 'USER');
  renderHome();
  expect(screen.getByText('Tablas')).toBeInTheDocument();
  expect(screen.getByText('Gráficos')).toBeInTheDocument();
  expect(screen.getByText('Evolución')).toBeInTheDocument();
  expect(screen.getByText('Críticas')).toBeInTheDocument();
  expect(screen.getByText('Resumen')).toBeInTheDocument();
  expect(screen.queryByText('Ajustes')).not.toBeInTheDocument();
  expect(screen.queryByText('Obtener datos desde Wazuh')).not.toBeInTheDocument();
});

test('renders admin-only items for ADMIN role', () => {
  localStorage.setItem('user_role', 'ADMIN');
  renderHome();
  expect(screen.getByText('Ajustes')).toBeInTheDocument();
  expect(screen.getByText('Obtener datos desde Wazuh')).toBeInTheDocument();
});

test('clicking a menu card navigates', () => {
  localStorage.setItem('user_role', 'USER');
  renderHome();
  const tablasBtn = screen.getByText('Tablas').closest('button');
  expect(tablasBtn).not.toBeNull();
  fireEvent.click(tablasBtn);
  expect(screen.getByText(/Tablas/i)).toBeInTheDocument();
});

test('admin Wazuh button navigates to consumer', () => {
  localStorage.setItem('user_role', 'ADMIN');
  renderHome();
  const wazuhBtn = screen.getByText('Obtener datos desde Wazuh').closest('button');
  expect(wazuhBtn).not.toBeNull();
  fireEvent.click(wazuhBtn);
});
