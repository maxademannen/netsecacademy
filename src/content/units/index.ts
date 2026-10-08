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

import type { Unit } from "../types";

export const UNITS: Unit[] = [unit1, unit2, unit3, unit4, unit5, unit6, unit7, unit8];

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
