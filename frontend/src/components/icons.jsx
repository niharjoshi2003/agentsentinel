export function ShieldLogo({ size = 38 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" fill="none" aria-hidden="true">
      <defs>
        <linearGradient id="shieldGrad" x1="0" y1="0" x2="48" y2="48">
          <stop offset="0%" stopColor="#38bdf8" />
          <stop offset="100%" stopColor="#22d3ee" />
        </linearGradient>
      </defs>
      <path
        d="M24 3l16 6v11c0 10.5-6.8 20-16 25-9.2-5-16-14.5-16-25V9l16-6z"
        fill="url(#shieldGrad)"
        fillOpacity="0.14"
        stroke="url(#shieldGrad)"
        strokeWidth="1.8"
      />
      <path
        d="M16 24.5l5.5 5.5L33 18.5"
        stroke="url(#shieldGrad)"
        strokeWidth="2.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function Icon({ name, className = "h-5 w-5" }) {
  const paths = {
    intercept: (
      <>
        <path d="M4 12h6m4 0h6" />
        <circle cx="12" cy="12" r="2.5" />
      </>
    ),
    threat: (
      <>
        <path d="M12 3l9 16H3l9-16z" />
        <path d="M12 10v4M12 17.5v.01" />
      </>
    ),
    critical: (
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M12 7v6M12 16.5v.01" />
      </>
    ),
    clean: (
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M8.5 12.5l2.5 2.5 4.5-5" />
      </>
    ),
    graph: (
      <>
        <circle cx="6" cy="6" r="2.4" />
        <circle cx="18" cy="9" r="2.4" />
        <circle cx="9" cy="18" r="2.4" />
        <path d="M8 7l8 1.5M8 16l1-7" />
      </>
    ),
    bolt: <path d="M13 2L4 14h7l-1 8 9-12h-7l1-8z" />,
    close: <path d="M6 6l12 12M18 6L6 18" />
  };
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      {paths[name]}
    </svg>
  );
}
