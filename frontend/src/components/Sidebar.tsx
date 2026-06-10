import { useT } from "../i18n";

export interface NavItem<T extends string> {
  key: T;
  label: string;
  description: string;
  icon: string;
}

interface SidebarFooterAction {
  label: string;
  glyph: string;
  onClick: () => void;
  active?: boolean;
  disabled?: boolean;
}

interface SidebarProps<T extends string> {
  activeView: T;
  activeNavView?: T;
  nav: NavItem<T>[];
  footerActions: SidebarFooterAction[];
  onSelectView: (view: T) => void;
}

export function Sidebar<T extends string>({ activeView, activeNavView = activeView, nav, footerActions, onSelectView }: SidebarProps<T>) {
  const { t } = useT();

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-badge">
          <img src="/icons/sidebar/brand-shield.svg" alt="" aria-hidden="true" />
        </div>
        <div>
          <div className="brand-kicker">{t("brand.name")}</div>
          <h1>{t("brand.name")}</h1>
          <p>{t("brand.tagline")}</p>
        </div>
      </div>

      <nav className="nav-list" aria-label="main navigation">
        {nav.map((item) => (
          <button
            key={item.key}
            type="button"
            className={`nav-item ${activeNavView === item.key ? "active" : ""}`}
            onClick={() => onSelectView(item.key)}
            title={item.label}
          >
            <span className="nav-icon" aria-hidden="true">
              <img src={item.icon} alt="" />
            </span>
            <span>
              <strong>{item.label}</strong>
              {item.description && <small>{item.description}</small>}
            </span>
          </button>
        ))}
      </nav>

      <div className="sidebar-footer">
        {footerActions.map((action) => (
          <button
            key={action.label}
            type="button"
            className={action.active ? "active" : ""}
            title={action.label}
            aria-label={action.label}
            disabled={action.disabled}
            onClick={action.onClick}
          >
            {action.glyph}
          </button>
        ))}
      </div>
    </aside>
  );
}
