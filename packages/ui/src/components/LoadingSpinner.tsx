import React from 'react';

interface LoadingSpinnerProps {
  size?: 'xs' | 'sm' | 'md' | 'lg';
  color?: 'blue' | 'white' | 'gray';
  className?: string;
}

const SIZE_CONFIG = {
  xs: 'h-3 w-3 border',
  sm: 'h-4 w-4 border',
  md: 'h-6 w-6 border-2',
  lg: 'h-8 w-8 border-2',
};

const COLOR_CONFIG = {
  blue: 'border-blue-500 border-t-transparent',
  white: 'border-white border-t-transparent',
  gray: 'border-gray-400 border-t-transparent',
};

export function LoadingSpinner({ size = 'md', color = 'blue', className = '' }: LoadingSpinnerProps) {
  return (
    <div
      className={`animate-spin rounded-full ${SIZE_CONFIG[size]} ${COLOR_CONFIG[color]} ${className}`}
      role="status"
      aria-label="Loading"
    />
  );
}

interface LoadingOverlayProps {
  message?: string;
  className?: string;
}

export function LoadingOverlay({ message = 'Loading...', className = '' }: LoadingOverlayProps) {
  return (
    <div className={`flex flex-col items-center justify-center gap-3 p-8 ${className}`}>
      <LoadingSpinner size="lg" />
      <p className="text-sm text-gray-400">{message}</p>
    </div>
  );
}
