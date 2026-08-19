import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, expect, test, vi } from 'vitest';
import Navbar from '../components/Navbar/Navbar';

beforeEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

test('renders logo text and separator', () => {
  render(<MemoryRouter><Navbar /></MemoryRouter>);
  expect(screen.getByText('VulnChecker')).toBeInTheDocument();
  expect(screen.getByText('|')).toBeInTheDocument();
  expect(screen.getByText('Cerrar Sesión')).toBeInTheDocument();
});

test('shows default user name when no stored user_name', () => {
  render(<MemoryRouter><Navbar /></MemoryRouter>);
  expect(screen.getByText('Usuario')).toBeInTheDocument();
});

test('shows stored user_name from localStorage', () => {
  localStorage.setItem('user_name', 'Juan');
  render(<MemoryRouter><Navbar /></MemoryRouter>);
  expect(screen.getByText('Juan')).toBeInTheDocument();
});

test('shows correct page title for known routes', () => {
  const routes = [
    { path: '/home', title: 'Panel Principal' },
    { path: '/settings', title: 'Configuración de API' },
    { path: '/tables', title: 'Explorador de Activos' },
    { path: '/charts', title: 'Análisis Métrico' },
    { path: '/evolution', title: 'Histórico' },
    { path: '/timeline', title: 'Timeline' },
    { path: '/critical', title: 'Alertas Críticas' },
    { path: '/logs', title: 'Bitácora de Eventos' },
  ];
  routes.forEach(({ path, title }) => {
    const { unmount } = render(<MemoryRouter initialEntries={[path]}><Navbar /></MemoryRouter>);
    expect(screen.getByText(title)).toBeInTheDocument();
    unmount();
  });
});

test('shows Gestión for unknown routes', () => {
  render(<MemoryRouter initialEntries={['/unknown']}><Navbar /></MemoryRouter>);
  expect(screen.getByText('Gestión')).toBeInTheDocument();
});

test('clicking logo navigates to /home', () => {
  render(<MemoryRouter initialEntries={['/settings']}><Navbar /></MemoryRouter>);
  fireEvent.click(screen.getByText('VulnChecker'));
});

test('pressing Enter on logo navigates to /home', () => {
  render(<MemoryRouter><Navbar /></MemoryRouter>);
  const logo = screen.getByText('VulnChecker');
  fireEvent.keyDown(logo, { key: 'Enter' });
});

test('pressing Space on logo navigates to /home', () => {
  render(<MemoryRouter><Navbar /></MemoryRouter>);
  const logo = screen.getByText('VulnChecker');
  fireEvent.keyDown(logo, { key: ' ' });
});

test('pressing other key on logo does nothing', () => {
  render(<MemoryRouter><Navbar /></MemoryRouter>);
  const logo = screen.getByText('VulnChecker');
  fireEvent.keyDown(logo, { key: 'Escape' });
});

test('clicking logout clears localStorage', () => {
  localStorage.setItem('is_authenticated', 'true');
  localStorage.setItem('user_name', 'test');
  render(<MemoryRouter><Navbar /></MemoryRouter>);
  fireEvent.click(screen.getByText('Cerrar Sesión'));
  expect(localStorage.getItem('is_authenticated')).toBeNull();
  expect(localStorage.getItem('user_name')).toBeNull();
});
