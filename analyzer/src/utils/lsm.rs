//! This module provides a simple linear state machine implementation.
//! The state machine can execute a series of steps, each represented by a function
//! that returns an `LSMAction` indicating the next action to take.

/// Represents the possible actions that can be taken by the linear state machine.
#[derive(Debug, PartialEq)]
pub enum LSMAction {
    /// Pause the lsm (waiting for more data)
    Pause,
    /// Go to the next step
    Next,
    /// Reset to step 1
    Reset,
    /// Cancel the processing
    Cancel,
}

/// The type of the funtciotns in the step.
pub type StepType<T> = Box<dyn Fn(&mut T) -> LSMAction + Send + Sync>;

/// A linear state machine that executes a series of steps in order.
/// Each step is a function that returns an `LSMAction` indicating the next action to take.
/// The state machine can be paused, reset, or cancelled based on the actions returned by the steps.
/// The generic type `T` is a struct which contains the LinearStateMachine field.
pub struct LinearStateMachine<T> {
    steps: Vec<StepType<T>>,
    index: usize,
    cancelled: bool,
}

impl<T> LinearStateMachine<T> {
    /// Creates a new LinearStateMachine with the given steps.
    ///
    /// # Arguments
    ///
    /// * `steps` - A vector of boxed functions that return an `LSMAction`.
    pub fn new(steps: Vec<StepType<T>>) -> Self {
        LinearStateMachine {
            steps,
            index: 0,
            cancelled: false,
        }
    }

    /// Runs the state machine from the current index.
    ///
    /// # Returns
    ///
    /// A tuple where the first element indicates if the state machine was cancelled,
    /// and the second element indicates if the state machine has completed all steps.
    pub fn run(&mut self, target: &mut T) -> (bool, bool) {
        if self.index >= self.steps.len() {
            return (self.cancelled, true);
        }

        while self.index < self.steps.len() {
            let action = (self.steps[self.index])(target);
            match action {
                LSMAction::Pause => return (false, false),
                LSMAction::Next => self.index += 1,
                LSMAction::Reset => self.index = 0,
                LSMAction::Cancel => {
                    self.cancelled = true;
                    return (true, true);
                }
            }
        }
        (false, true)
    }

    /// Appends additional steps to the state machine.
    ///
    /// # Arguments
    ///
    /// * `steps` - A vector of boxed functions that return an `LSMAction`.
    pub fn append_steps(&mut self, steps: Vec<StepType<T>>) {
        self.steps.extend(steps);
    }

    /// Resets the state machine to the initial state.
    pub fn reset(&mut self) {
        self.index = 0;
        self.cancelled = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestState {
        value: i32,
    }

    fn step_increment(state: &mut TestState) -> LSMAction {
        state.value += 1;
        LSMAction::Next
    }

    #[allow(unused_variables)]
    fn step_pause(state: &mut TestState) -> LSMAction {
        LSMAction::Pause
    }

    #[test]
    fn test_run() {
        let steps: Vec<StepType<TestState>> = vec![Box::new(step_increment), Box::new(step_pause)];
        let mut lsm = LinearStateMachine::new(steps);
        let mut state = TestState { value: 0 };

        // Test running the state machine
        let (cancelled, completed) = lsm.run(&mut state);
        assert_eq!(state.value, 1);
        assert_eq!(cancelled, false);
        assert_eq!(completed, false);
    }

    #[test]
    fn test_append_steps() {
        let initial_steps: Vec<StepType<TestState>> = vec![Box::new(step_increment)];
        let mut lsm = LinearStateMachine::new(initial_steps);
        let mut state = TestState { value: 0 };

        lsm.run(&mut state);
        assert_eq!(state.value, 1);

        let additional_steps: Vec<StepType<TestState>> = vec![Box::new(step_increment)];
        lsm.append_steps(additional_steps);

        lsm.run(&mut state);
        assert_eq!(state.value, 2);
    }

    #[test]
    fn test_reset() {
        let steps: Vec<StepType<TestState>> = vec![Box::new(step_increment), Box::new(step_pause)];
        let mut lsm = LinearStateMachine::new(steps);
        let mut state = TestState { value: 0 };

        lsm.run(&mut state);
        assert_eq!(state.value, 1);

        lsm.reset();
        assert_eq!(lsm.index, 0);
        assert_eq!(lsm.cancelled, false);

        lsm.run(&mut state);
        assert_eq!(state.value, 2);
    }
}
