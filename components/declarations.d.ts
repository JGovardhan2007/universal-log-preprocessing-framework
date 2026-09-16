// Ambient type declarations for React, JSX, and Aceternity UI component dependencies

declare namespace JSX {
  interface Element {}
  interface IntrinsicElements {
    [elemName: string]: any;
  }
}

declare module "react" {
  export function useRef<T>(initialValue?: T | null): { current: T };
  export function useState<T>(initialState: T | (() => T)): [T, (newState: T | ((prev: T) => T)) => void];
  export function useEffect(effect: () => void | (() => void), deps?: readonly any[]): void;
  export type ReactNode = any;
  export type FC<P = {}> = (props: P) => any;
  export type SVGProps<T> = any;
  export type HTMLAttributes<T> = any;
  const React: any;
  export default React;
}

declare module "react/jsx-runtime" {
  export namespace JSX {
    interface Element {}
    interface IntrinsicElements {
      [elemName: string]: any;
    }
  }
  export const jsx: any;
  export const jsxs: any;
  export const Fragment: any;
}

declare module "react/jsx-dev-runtime" {
  export namespace JSX {
    interface Element {}
    interface IntrinsicElements {
      [elemName: string]: any;
    }
  }
  export const jsxDEV: any;
  export const Fragment: any;
}

declare module "motion/react" {
  export const motion: {
    div: any;
    span: any;
    p: any;
    path: any;
    circle: any;
    svg: any;
    [key: string]: any;
  };
  export const AnimatePresence: any;
}

declare module "dotted-map" {
  export default class DottedMap {
    constructor(options?: { height?: number; grid?: string });
    getSVG(options?: {
      radius?: number;
      color?: string;
      shape?: string;
      backgroundColor?: string;
    }): string;
  }
}

declare module "next-themes" {
  export function useTheme(): {
    theme?: string;
    setTheme: (theme: string) => void;
    systemTheme?: string;
  };
}
