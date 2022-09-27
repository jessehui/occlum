use std::any::Any;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Weak;

use super::{Event, EventFilter, Observer};
use crate::prelude::*;

/// An event notifier broadcasts interesting events to registered observers.
pub struct Notifier<E: Event, F: EventFilter<E> = DummyEventFilter<E>> {
    subscribers: SgxMutex<VecDeque<Subscriber<E, F>>>,
}

impl<E: Event, F: EventFilter<E>> Clone for Notifier<E, F> {
    fn clone(&self) -> Self {
        let subscribers = self.subscribers.lock().unwrap();
        let new_subscribers = (*subscribers).clone();
        Self {
            subscribers: SgxMutex::new(new_subscribers),
        }
    }
}

struct Subscriber<E: Event, F: EventFilter<E>> {
    observer: Weak<dyn Observer<E>>,
    filter: Option<F>,
    metadata: Option<Weak<dyn Any + Send + Sync>>,
}

impl<E: Event, F: EventFilter<E>> Clone for Subscriber<E, F> {
    fn clone(&self) -> Self {
        Self {
            observer: self.observer.clone(),
            filter: self.filter.clone(),
            metadata: self.metadata.clone(),
        }
    }
}

impl<E: Event, F: EventFilter<E>> Notifier<E, F> {
    /// Create an event notifier.
    pub fn new() -> Self {
        let subscribers = SgxMutex::new(VecDeque::new());
        Self { subscribers }
    }

    /// Register an observer with its interesting events and metadata.
    pub fn register(
        &self,
        observer: Weak<dyn Observer<E>>,
        filter: Option<F>,
        metadata: Option<Weak<dyn Any + Send + Sync>>,
    ) {
        let mut subscribers = self.subscribers.lock().unwrap();
        subscribers.push_back(Subscriber {
            observer,
            filter,
            metadata,
        });
    }

    /// Unregister an observer.
    pub fn unregister(&self, observer: &Weak<dyn Observer<E>>) {
        let mut subscribers = self.subscribers.lock().unwrap();
        subscribers.retain(|subscriber| !Weak::ptr_eq(&subscriber.observer, observer));
    }

    /// Broadcast an event to all registered observers.
    pub fn broadcast(&self, event: &E) {
        let subscribers = self.subscribers.lock().unwrap();
        info!("subscribers number = {:?}", subscribers.len());
        for subscriber in subscribers.iter() {
            if let Some(filter) = subscriber.filter.as_ref() {
                if !filter.filter(event) {
                    continue;
                }
            }
            info!("broadcast event 1");
            let observer = match subscriber.observer.upgrade() {
                // TODO: should remove subscribers whose observers have been freed
                None => return,
                Some(observer) => observer,
            };

            info!("broadcast event");
            observer.on_event(event, &subscriber.metadata);
        }
    }
}

impl<E: Event, F: EventFilter<E>> fmt::Debug for Notifier<E, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Notifier {{ .. }}")
    }
}

#[derive(Clone)]
pub struct DummyEventFilter<E> {
    phantom: PhantomData<E>,
}

impl<E: Event> EventFilter<E> for DummyEventFilter<E> {
    fn filter(&self, event: &E) -> bool {
        true
    }
}
