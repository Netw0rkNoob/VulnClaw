import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { loadUiPreferences, subscribeUiPreferences, type UiPreferences } from "../utils/preferences";
import en from "./en.json";
import zh from "./zh.json";

type Lang = "zh-CN" | "en-US";
type Translations = Record<string, string>;
export type TFunction = (key: string, params?: Record<string, string>, fallback?: string) => string;

const TRANSLATIONS: Record<Lang, Translations> = {
  "en-US": en as Translations,
  "zh-CN": zh as Translations,
};

/* ── 全局单例（供 taskLabels 等非 React 代码使用）── */

let _currentLang: Lang = resolveInitialLang();
let _currentTranslations: Translations = TRANSLATIONS[_currentLang];

function resolveInitialLang(): Lang {
  try {
    const preferences = loadUiPreferences();
    return preferences.language === "zh-CN" ? "zh-CN" : "en-US";
  } catch {
    return "en-US";
  }
}

/**
 * 全局翻译函数 — 可在 React 组件之外调用。
 *   t("key")                -> 翻译文本
 *   t("key", {a:"1"})       -> 替换 {a} 占位符
 *   t("key", {}, "fallback") -> key 不存在时使用 fallback
 *
 * 保底链：当前语言 → 英文 → key 本身（或 fallback）
 */
export function t(key: string, params?: Record<string, string>, fallback?: string): string {
  let text = _currentTranslations[key];
  if (text === undefined) {
    text = TRANSLATIONS["en-US"][key];
  }
  if (text === undefined) {
    text = fallback ?? key;
  }
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      text = text.replace(`{${k}}`, String(v));
    }
  }
  return text;
}

/* ── React Context ── */

interface I18nContextValue {
  lang: Lang;
  t: (key: string, params?: Record<string, string>, fallback?: string) => string;
}

const I18nContext = createContext<I18nContextValue>({
  lang: _currentLang,
  t,
});

/**
 * React Hook — 组件使用 `const { t, lang } = useT()` 获取翻译函数。
 * 当语言切换时自动触发重渲染。
 */
export function useT(): I18nContextValue {
  return useContext(I18nContext);
}

/**
 * I18nProvider — 在 main.tsx 中包裹 <App />。
 * 监听 preferences 变化，语言切换时更新 Context 和全局单例。
 */
export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLang] = useState<Lang>(_currentLang);

  useEffect(() => {
    const unsubscribe = subscribeUiPreferences((preferences: UiPreferences) => {
      const nextLang: Lang = preferences.language === "zh-CN" ? "zh-CN" : "en-US";
      if (nextLang !== _currentLang) {
        _currentLang = nextLang;
        _currentTranslations = TRANSLATIONS[nextLang];
        setLang(nextLang);
      }
    });
    return unsubscribe;
  }, []);

  const value = useMemo<I18nContextValue>(() => {
    const tFn: TFunction = (key, params, fallback) => {
      let text = TRANSLATIONS[lang][key];
      if (text === undefined) text = TRANSLATIONS["en-US"][key];
      if (text === undefined) text = fallback ?? key;
      if (params) {
        for (const [k, v] of Object.entries(params)) text = text.replace(`{${k}}`, String(v));
      }
      return text;
    };
    return { lang, t: tFn };
  }, [lang]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}
