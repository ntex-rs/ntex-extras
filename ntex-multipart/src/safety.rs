use ntex::task::LocalWaker;
use std::cell::Cell;
use std::marker::PhantomData;
use std::rc::Rc;
use std::task::Context;

/// Counter. It tracks of number of clones of payloads and give access to
/// payload only to top most task panics if Safety get destroyed and it not top
/// most task.
#[derive(Debug)]
pub(crate) struct Safety {
    task: LocalWaker,
    level: usize,
    payload: Rc<PhantomData<bool>>,
    clean: Rc<Cell<bool>>,
}

impl Safety {
    pub(crate) fn new() -> Safety {
        let payload = Rc::new(PhantomData);
        Safety {
            task: LocalWaker::new(),
            level: Rc::strong_count(&payload),
            clean: Rc::new(Cell::new(true)),
            payload,
        }
    }

    pub(crate) fn current(&self) -> bool {
        Rc::strong_count(&self.payload) == self.level && self.clean.get()
    }

    pub(crate) fn is_clean(&self) -> bool {
        self.clean.get()
    }

    pub(crate) fn clone(&self, cx: &mut Context) -> Safety {
        let payload = Rc::clone(&self.payload);
        let s = Safety {
            task: LocalWaker::new(),
            level: Rc::strong_count(&payload),
            clean: self.clean.clone(),
            payload,
        };
        s.task.register(cx.waker());
        s
    }
}

impl Drop for Safety {
    fn drop(&mut self) {
        // parent task is dead
        if Rc::strong_count(&self.payload) != self.level {
            self.clean.set(true);
        }
        if let Some(task) = self.task.take() {
            task.wake()
        }
    }
}
