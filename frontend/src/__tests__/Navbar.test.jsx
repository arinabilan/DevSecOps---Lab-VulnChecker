import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, test, vi } from 'vitest';
import Navbar from '../components/Navbar/Navbar';

beforeEach(() => {
  vi.restoreAllMocks();
});

test('renders logo text', () => {
  render(<MemoryRouter><Navbar /></MemoryRouter>);
  expect(screen.getByText('VulnChecker')).toBeInTheDocument();
});

test('renders separator', () => {
  render(<MemoryRouter><Navbar /></MemoryRouter>);
  expect(screen.getByText('|')).toBeInTheDocument();
});

test('renders logout button', () => {
  render(<MemoryRouter><Navbar /></MemoryRouter>);
  expect(screen.getByText('Cerrar Sesión')).toBeInTheDocument();
});

test('clicking logo navigates to /home', () => {
  render(<MemoryRouter><Navbar /></MemoryRouter>);
  const logo = screen.getByText('VulnChecker');
  fireEvent.click(logo);
});

test('clicking logout clears localStorage', () => {
  localStorage.setItem('is_authenticated', 'true');
  localStorage.setItem('user_name', 'test');
  render(<MemoryRouter><Navbar /></MemoryRouter>);
  fireEvent.click(screen.getByText('Cerrar Sesión'));
  expect(localStorage.getItem('is_authenticated')).toBeNull();
});
