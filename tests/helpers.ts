import timekeeper from 'timekeeper'
import { getActiveTest } from '@japa/runner'

/**
 * Travels time by seconds
 */
export function timeTravel(secondsToTravel: number) {
  const test = getActiveTest()
  if (!test) {
    throw new Error('Cannot use "timeTravel" outside of a Japa test')
  }

  timekeeper.reset()

  const date = new Date()
  date.setSeconds(date.getSeconds() + secondsToTravel)
  timekeeper.travel(date)

  test.cleanup(() => {
    timekeeper.reset()
  })
}

/**
 * Freezes time in the moment
 */
export function freezeTime() {
  const test = getActiveTest()
  if (!test) {
    throw new Error('Cannot use "freezeTime" outside of a Japa test')
  }

  timekeeper.reset()

  const date = new Date()
  timekeeper.freeze(date)

  test.cleanup(() => {
    timekeeper.reset()
  })
}
