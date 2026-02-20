/**
 * @file ts_scheduler.h
 * @brief Single-header, Vulkan-flavored task scheduler with explicit synchronization primitives.
 *
 * @author Charles 'xtrium' Riffaud-Declercq
 * @license CC BY-SA 4.0 - https://creativecommons.org/licenses/by-sa/4.0/
 *
 * Usage:
 *   Define TS_SCHEDULER_IMPLEMENTATION in exactly one translation unit before including this header.
 *
 * Example:
 * @code
 *   #define TS_SCHEDULER_IMPLEMENTATION
 *   #include <ts/ts_scheduler.h>
 *
 *   ts::Scheduler scheduler;
 *   ts::Semaphore sem  {};
 *   ts::Fence     done {};
 *
 *   scheduler.Submit({
 *       .task = [] { do_work(); },
 *       .signalSemaphores = { sem }
 *   });
 *   scheduler.Submit({
 *       .task = [] { do_more_work(); },
 *       .waitSemaphores = { sem },
 *       .signalFence = done
 *   });
 *
 *   done.Wait();
 * @endcode
 */

#ifndef TS_SCHEDULER_H
#define TS_SCHEDULER_H

#include <memory>
#include <functional>
#include <optional>
#include <queue>
#include <semaphore>
#include <thread>
#include <mutex>

namespace ts
{
	/**
	 * @brief A shareable, binary signaling primitive.
	 *
	 * Semaphores are lightweight handles backed by shared state, and are safe to copy.
	 * Multiple copies refer to the same underlying semaphore.
	 *
	 * Used in @ref SubmitInfo to express task dependencies: a task will not execute
	 * until all of its wait semaphores have been signaled.
	 */
	class Semaphore
	{
		struct State;
		std::shared_ptr<State> m_state;

	public:
		Semaphore();

		/** @brief Signals the semaphore, unblocking one waiter. */
		void Signal() const;

		/** @brief Blocks until the semaphore is signaled, then consumes the signal. */
		void Wait() const;

		/** @brief Drains any pending signal without blocking. No-op if not signaled. */
		void Reset() const;

		/** @brief Attempts to consume the signal without blocking. @return true if the signal was consumed. */
		[[nodiscard]] bool TryWait() const;

		/** @brief Checks whether the semaphore is currently signaled without consuming the signal. @return true if signaled. */
		[[nodiscard]] bool IsSignaled() const;
	};

	/**
	 * @brief A one-shot, reusable completion event.
	 *
	 * Unlike @ref Semaphore, a Fence latches: once signaled, all waiters are
	 * unblocked and subsequent waits return immediately until the fence is reset.
	 *
	 * Fences are not copyable by value - construct directly.
	 */
	class Fence
	{
		struct State;
		std::shared_ptr<State> m_state;

	public:
		/** @brief Constructs a fence, optionally pre-signaled. */
		explicit Fence(bool signaled = false);

		/** @brief Blocks until the fence is signaled. Returns immediately if already signaled. */
		void Wait();

		/** @brief Signals the fence. Has no effect if already signaled. */
		void Signal();

		/** @brief Resets the fence to the unsignaled state. */
		void Reset();
	};

	/**
	 * @brief Describes a unit of work to be submitted to the @ref Scheduler.
	 *
	 * Execution of @p task is deferred until all @p waitSemaphores are signaled.
	 * After the task completes, all @p signalSemaphores are signaled and @p signalFence
	 * (if provided) is signaled.
	 */
	struct SubmitInfo
	{
		std::function<void()>  task;
		std::vector<Semaphore> waitSemaphores   = {}; ///< Semaphores that must be signaled before the task runs.
		std::vector<Semaphore> signalSemaphores = {}; ///< Semaphores to signal after the task completes.
		std::optional<Fence>   signalFence      = {}; ///< Optional fence to signal after the task completes.
	};

	/**
	 * @brief A multi-threaded task scheduler with dependency tracking.
	 *
	 * Maintains a pool of worker threads that pull tasks from a shared queue.
	 * Tasks that declare wait semaphores are requeued until their dependencies
	 * are satisfied, enabling graph-style execution ordering.
	 *
	 * The scheduler is non-copyable. Destruction blocks until all workers have exited.
	 *
	 * @note Tasks whose dependencies are never satisfied will spin indefinitely.
	 *       Ensure all signaling tasks are eventually submitted.
	 */
	class Scheduler
	{
		void m_Enqueue(SubmitInfo info);
		void m_WorkerLoop(std::stop_token st);

		std::vector<std::jthread>   m_workers;
		std::queue<SubmitInfo>      m_queue;
		std::mutex                  m_mutex;
		std::counting_semaphore<>   m_queueSemaphore;

	public:
		/**
		 * @brief Constructs the scheduler and spawns worker threads.
		 * @param threadCount Number of worker threads. Defaults to hardware_concurrency - 1, minimum 1.
		 */
		explicit Scheduler(std::size_t threadCount = 0);

		/** @brief Signals all workers to stop and joins them. */
		~Scheduler();

		Scheduler(const Scheduler&) = delete;
		Scheduler& operator=(const Scheduler&) = delete;

		/** @brief Returns the number of worker threads. */
		std::size_t ThreadCount() const;

		/**
		 * @brief Submits a task for asynchronous execution.
		 *
		 * The task is queued immediately but will only execute once all
		 * wait semaphores in @p info are signaled.
		 */
		void Submit(SubmitInfo info);
	};
}

#endif /* TS_SCHEDULER_H */

#if defined(TS_SCHEDULER_IMPLEMENTATION) && !defined(TS_SCHEDULER_BODY_IMPLEMENTED)
#define TS_SCHEDULER_BODY_IMPLEMENTED
namespace ts
{
	struct Semaphore::State
	{
		std::binary_semaphore semaphore { 0 };
	};

	struct Fence::State
	{
		std::atomic<bool>     signaled;
		std::binary_semaphore semaphore { 0 };

		State(bool signaled)
			: signaled(signaled)
			, semaphore(signaled ? 1 : 0)
		{}
	};

	// ------------------------------------------------------------------------

	Semaphore::Semaphore()
		: m_state(std::make_shared<State>())
	{}

	void Semaphore::Signal() const
	{
		m_state->semaphore.release();
	}

	void Semaphore::Wait() const
	{
		m_state->semaphore.acquire();
	}

	bool Semaphore::TryWait() const
	{
		return m_state->semaphore.try_acquire();
	}

	bool Semaphore::IsSignaled() const
	{
		bool result = m_state->semaphore.try_acquire();
		if (result)
			m_state->semaphore.release();

		return result;
	}

	void Semaphore::Reset() const
	{ // Drain signal if there's one, no-op otherwise
		std::ignore = m_state->semaphore.try_acquire();
	}

	// ------------------------------------------------------------------------

	Fence::Fence(bool signaled /* = false */)
		: m_state(std::make_shared<State>(signaled))
	{
	}

	void Fence::Wait()
	{
		m_state->semaphore.acquire();
		m_state->semaphore.release();
	}

	void Fence::Signal()
	{
		bool expected = false;
		if (m_state->signaled.compare_exchange_strong(expected, true))
			m_state->semaphore.release();
	}

	void Fence::Reset()
	{
		bool expected = true;
		if (m_state->signaled.compare_exchange_strong(expected, false))
			m_state->semaphore.acquire();
	}

	// ------------------------------------------------------------------------

	Scheduler::Scheduler(std::size_t threadCount /* = 0 */)
		: m_queueSemaphore(0)
	{
		if (threadCount == 0)
			threadCount = std::max(1u, std::thread::hardware_concurrency() - 1);

		m_workers.reserve(threadCount);

		for (std::size_t i = 0; i < threadCount; ++i)
			m_workers.emplace_back([this](std::stop_token st) { m_WorkerLoop(st); });
	}

	Scheduler::~Scheduler()
	{
		for (auto& w : m_workers)
			w.request_stop();

		m_queueSemaphore.release(m_workers.size());
	}

	std::size_t Scheduler::ThreadCount() const
	{
		return m_workers.size();
	}

	void Scheduler::Submit(SubmitInfo info)
	{
		m_Enqueue(std::move(info));
	}

	void Scheduler::m_Enqueue(SubmitInfo info)
	{
		{
			std::scoped_lock lock(m_mutex);
			m_queue.push(std::move(info));
		}

		m_queueSemaphore.release();
	}

	void Scheduler::m_WorkerLoop(std::stop_token st)
	{
		while (!st.stop_requested())
		{
			m_queueSemaphore.acquire();

			if (st.stop_requested())
				return;

			SubmitInfo info;
			{
				std::scoped_lock lock(m_mutex);
				info = std::move(m_queue.front());
				m_queue.pop();
			}

			bool ready = true;
			for (auto& sem : info.waitSemaphores)
			{
				if (!sem.IsSignaled())
				{
					ready = false;
					break;
				}
			}

			if (!ready)
			{
				{
					std::scoped_lock lock(m_mutex);
					m_queue.push(std::move(info));
				}

				m_queueSemaphore.release();
				continue;
			}

			if (info.task)
				info.task();

			for (auto& sem : info.signalSemaphores)
				sem.Signal();

			if (info.signalFence)
				info.signalFence->Signal();
		}
	}
}
#endif /* TS_SCHEDULER_IMPLEMENTATION */
