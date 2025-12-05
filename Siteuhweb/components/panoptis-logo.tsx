export function PanoptisLogo({ className = '' }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 180 50"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
    >
      {/* Shield with eye */}
      <path
        d="M25 5L10 12V22C10 30 17 37 25 40C33 37 40 30 40 22V12L25 5Z"
        fill="currentColor"
        opacity="0.2"
      />
      <path
        d="M25 5L10 12V22C10 30 17 37 25 40C33 37 40 30 40 22V12L25 5Z"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      {/* Eye */}
      <ellipse cx="25" cy="23" rx="8" ry="5" stroke="currentColor" strokeWidth="1.5" />
      <circle cx="25" cy="23" r="3" fill="currentColor" />
      
      {/* Text */}
      <text x="52" y="32" fontFamily="Inter, sans-serif" fontSize="20" fontWeight="700" fill="currentColor">
        Panoptis
      </text>
    </svg>
  )
}
