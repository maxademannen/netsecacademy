import { resetIds } from "../pkt";
resetIds();

import unit1 from "./unit1";
import unit2 from "./unit2";
import unit3 from "./unit3";
import unit4 from "./unit4";
import unit5 from "./unit5";
import unit6 from "./unit6";
import unit7 from "./unit7";
import unit8 from "./unit8";

import { extraLessons as extra1 } from "./unit1.extra";
import { extraLessons as extra2 } from "./unit2.extra";
import { extraLessons as extra3 } from "./unit3.extra";
import { extraLessons as extra4 } from "./unit4.extra";
import { extraLessons as extra5 } from "./unit5.extra";
import { extraLessons as extra6 } from "./unit6.extra";
import { extraLessons as extra7 } from "./unit7.extra";
import { extraLessons as extra8 } from "./unit8.extra";

import type { Unit } from "../types";

/** Merge expanded lesson sets into each unit without mutating the originals. */
function withExtras(u: Unit, extras: Unit["lessons"]): Unit {
  return { ...u, lessons: [...u.lessons, ...extras] };
}

export const UNITS: Unit[] = [
  withExtras(unit1, extra1),
  withExtras(unit2, extra2),
  withExtras(unit3, extra3),
  withExtras(unit4, extra4),
  withExtras(unit5, extra5),
  withExtras(unit6, extra6),
  withExtras(unit7, extra7),
  withExtras(unit8, extra8),
];

export function getUnit(id: string): Unit | undefined {
  return UNITS.find((u) => u.id === id);
}

export function getLesson(unitId: string, lessonId: string) {
  const u = getUnit(unitId);
  return u ? { unit: u, lesson: u.lessons.find((l) => l.id === lessonId) } : null;
}

export function totalLessons() {
  return UNITS.reduce((n, u) => n + u.lessons.length, 0);
}
