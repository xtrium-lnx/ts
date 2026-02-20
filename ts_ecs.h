/**
 * @file ts_ecs.h
 * @brief Single-header, data-oriented Entity-Component-System scene.
 *
 * @author Charles 'xtrium' Riffaud-Declercq
 * @license CC BY-SA 4.0 - https://creativecommons.org/licenses/by-sa/4.0/
 *
 * Usage:
 *   Just include and use.
 *
 * Concepts:
 *   * Entity   : a lightweight, generation-aware handle. Cheap to copy, safe to store.
 *   * Component: any plain struct or class. No base class, no macros required.
 *   * System   : any callable (function, lambda) - just call Scene::Query and iterate.
 *
 * Example:
 * @code
 *   #include <ts/ts_ecs.h>
 *
 *   struct Velocity  { float dx, dy, dz; };
 *   struct Health    { int hp; };
 *
 *   ts::Scene scene;
 *
 *   auto e1 = scene.Spawn();
 *   scene.Add<Velocity>(e1, { 1.f, 0.f, 0.f });
 *   scene.Add<Health>(e1, { 100 });
 *
 *   auto e2 = scene.Spawn();
 *   scene.Add<Health>(e2, { 50 });
 *
 *   float dt = getDeltaTimeSomehow();
 * 
 *   // Movement system: all entities with both Transform and Velocity.
 *   scene.Query<Transform, Velocity>().Each([dt](ts::Entity, Transform& t, Velocity& v) {
 *       t.transform += v.speed * dt;
 *   });
 *
 *   // Filter: entities with Health whose hp < 75
 *   scene.Query<Health>()
 *        .Where([&](ts::Entity e, const Health& h) {
 *            return h.hp < 75;
 *        })
 *        .Each([](ts::Entity e, Health& h) {
 *            // heal them or flag them...
 *        });
 *
 *   // Distance filter: entities with Transform within 10 units of origin.
 *   glm::vec3 origin { 0, 0, 0 };
 *   scene.Query<Transform>()
 *        .Where([&](ts::Entity, const Transform& t) {
 *            return glm::distance(t.position, origin) < 100.0f;
 *        })
 *        .Each([](ts::Entity e, Transform& t) { doSomething(); });
 *
 *    scene.Kill(e1); // e1 is now a dangling handle; all its components are removed.
 * @endcode
 */

#ifndef TS_ECS_H
#define TS_ECS_H

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <functional>
#include <memory>
#include <tuple>
#include <typeindex>
#include <unordered_map>
#include <vector>

namespace ts
{
    /**
     * @brief A lightweight, generation-aware entity handle.
     *
     * The upper 32 bits hold a generation counter; the lower 32 bits hold the
     * index within the scene's entity table. This lets the scene cheaply detect
     * stale handles: if you store an Entity and the entity is later killed and
     * the slot reused, @ref Scene::IsAlive will return false.
     *
     * Entities are trivially copyable and comparable.
     */
    struct Entity
    {
        static constexpr std::uint64_t kNULL_ID = std::uint64_t(-1);

        std::uint64_t id = kNULL_ID;

        operator bool() const { return id != kNULL_ID; }

        bool operator==(const Entity&) const = default;
        bool operator!=(const Entity&) const = default;
    };

    /** @brief The null entity - an entity that is never alive. */
    inline constexpr Entity NullEntity { Entity::kNULL_ID };
}

 template<>
 struct std::hash<ts::Entity>
 {
     std::size_t operator()(ts::Entity e) const noexcept
     {
         return std::hash<std::uint64_t>{}(e.id);
     }
 };

namespace ts
{
    // =========================================================================
    // Internal: SparseSet
    //
    // Stores components of a single type. Provides O(1) add/remove/lookup and
    // cache-friendly dense iteration.
    //
    // Layout:
    //   m_dense : contiguous array of { entity, item } pairs.
    //   m_sparse: entity-index -> position in m_dense.
    // =========================================================================

    namespace detail
    {
        /**
        * @brief Type-erased base so the Scene can hold heterogeneous sparse sets.
        */
        struct ISparseSet
        {
            virtual ~ISparseSet() = default;

            /** @brief Remove the item for @p e, if present. */
            virtual void Remove(Entity e) = 0;

            /** @brief Returns true if @p e has a item in this set. */
            [[nodiscard]] virtual bool Contains(Entity e) const = 0;
        };

        /**
         * @brief Typed sparse set for item type @p T.
         *
         * The dense array stores (Entity, T) pairs so iteration visits only live
         * components without any extra indirection.
         */
        template<typename T>
        class SparseSet final
            : public ISparseSet
        {
            struct Entry
            {
                Entity entity;
                T      item;
            };

            std::vector<Entry>                      m_dense;
            std::unordered_map<Entity, std::size_t> m_sparse; // entity -> index in m_dense

        public:
            /** @brief Add or replace the item for @p e. */
            template<typename... Args>
            T& Emplace(Entity e, Args&&... args)
            {
                auto it = m_sparse.find(e);
                if (it != m_sparse.end())
                {
                    m_dense[it->second].item = T{ std::forward<Args>(args)... };
                    return m_dense[it->second].item;
                }

                m_sparse[e] = m_dense.size();
                return m_dense.emplace_back(Entry{ e, T { std::forward<Args>(args)... } }).item;
            }

            void Remove(Entity e) override
            {
                auto it = m_sparse.find(e);
                if (it == m_sparse.end())
                    return;

                const std::size_t idx = it->second;
                const std::size_t last = m_dense.size() - 1;

                if (idx != last)
                {
                    m_dense[idx] = std::move(m_dense[last]);
                    m_sparse[m_dense[idx].entity] = idx;
                }

                m_dense.pop_back();
                m_sparse.erase(it);
            }

            [[nodiscard]] bool Contains(Entity e) const override
            {
                return m_sparse.contains(e);
            }

            /** @brief Returns a pointer to the item, or nullptr if not present. */
            [[nodiscard]] T* Get(Entity e)
            {
                auto it = m_sparse.find(e);
                return it != m_sparse.end() ? &m_dense[it->second].item : nullptr;
            }

            [[nodiscard]] const T* Get(Entity e) const
            {
                auto it = m_sparse.find(e);
                return it != m_sparse.end() ? &m_dense[it->second].item : nullptr;
            }

            /** @brief Iterates all (entity, item) pairs in arbitrary order. */
            template<typename Fn>
            void ForEach(Fn&& fn)
            {
                for (auto& entry : m_dense)
                    if (!fn(entry.entity, entry.item))
                        break;
            }

            [[nodiscard]] std::size_t Size()  const { return m_dense.size(); }
            [[nodiscard]] bool        Empty() const { return m_dense.empty(); }
        };
    }

    class Scene;

    /**
     * @brief A lazy, filterable view over entities that possess all of @p COMPONENTS.
     *
     * Constructed by @ref Scene::Query. Chain @ref Where to add predicates,
     * then call @ref Each to iterate.
     *
     * @tparam COMPONENTS Component types the entity must possess.
     */
    template<typename... COMPONENTS>
    class QueryView
    {
        static_assert(sizeof...(COMPONENTS) >= 1, "ts_ecs: Query requires at least one component type.");

        using FilterFn = std::function<bool(Entity, const COMPONENTS&...)>;
        using EachFn   = std::function<void(Entity, COMPONENTS&...)>;

        Scene* m_scene;
        std::tuple<detail::SparseSet<COMPONENTS>*...> m_sets;
        std::vector<FilterFn>                         m_filters;

        template<typename Fn>
        void m_Iterate(Fn&& fn)
        {
            auto& primary = *std::get<0>(m_sets);
            primary.ForEach([&](Entity e, auto& first) -> bool {
                if (!(std::get<detail::SparseSet<COMPONENTS>*>(m_sets)->Get(e) && ...))
                    return true;

                for (auto& filter : m_filters)
                    if (!filter(e, *std::get<detail::SparseSet<COMPONENTS>*>(m_sets)->Get(e)...))
                        return true;

                return fn(e, *std::get<detail::SparseSet<COMPONENTS>*>(m_sets)->Get(e)...);
            });
        }

    public:
        QueryView(Scene* scene, detail::SparseSet<COMPONENTS>*... sets)
            : m_scene(scene)
            , m_sets(sets...)
        {
        }

        /**
         * @brief Adds a filter predicate.
         *
         * The predicate receives the entity and const-refs to all queried components.
         * It can close over @p scene (or anything else) to express arbitrary conditions
         * such as distance checks, item-existence tests on other types, etc.
         *
         * Multiple Where() calls are ANDed together.
         *
         * @return *this for chaining.
         */
        QueryView& Where(FilterFn filter)
        {
            m_filters.push_back(std::move(filter));
            return *this;
        }

        /**
         * @brief Iterates all matching entities, calling @p fn for each.
         *
         * Iteration visits entities that:
         *   1. Possess every item in @p COMPONENTS.
         *   2. Pass every predicate added via @ref Where.
         */
        void Each(EachFn fn)
        {
            m_Iterate([&](Entity e, COMPONENTS&... components) {
                fn(e, components...);
                return true;
            });
        }

        /**
         * @brief Calls @p fn for only the first matching entity.
         */
        void Single(EachFn fn)
        {
            m_Iterate([&](Entity e, COMPONENTS&... components) {
                fn(e, components...);
                return false;
            });
        }

        /**
         * @brief Collects matching entities into a vector without iterating their components.
         *
         * Useful when you need a snapshot of entity handles (ie. to feed into another query
         * or to defer destruction).
         */
        [[nodiscard]] std::vector<Entity> Collect()
        {
            std::vector<Entity> result;
            Each([&](Entity e, COMPONENTS&...) { result.push_back(e); });
            return result;
        }
    };

    /**
     * @brief Manages entities and their components.
     *
     * Thread safety: none. The Scene class is designed for single-threaded use per frame.
     * If you need parallel systems, partition entities or use external locking.
     */
    class Scene
    {
        struct Slot
        {
            std::uint32_t generation = 0;
            bool          alive      = false;
        };

        std::vector<Slot>          m_slots;
        std::vector<std::uint32_t> m_freeList;

        std::unordered_map<std::type_index, std::unique_ptr<detail::ISparseSet>> m_sets;

        template<typename T>
        detail::SparseSet<T>& m_GetOrCreate()
        {
            auto key = std::type_index(typeid(T));
            auto it = m_sets.find(key);
            if (it == m_sets.end())
                it = m_sets.emplace(key, std::make_unique<detail::SparseSet<T>>()).first;
            return static_cast<detail::SparseSet<T>&>(*it->second);
        }

        template<typename T>
        detail::SparseSet<T>* m_Find()
        {
            auto it = m_sets.find(std::type_index(typeid(T)));
            return it != m_sets.end()
                ? static_cast<detail::SparseSet<T>*>(it->second.get())
                : nullptr;
        }

    public:
        /**
         * @brief Creates a new entity with no components.
         * @return A valid, alive entity handle.
         */
        [[nodiscard]] Entity Spawn()
        {
            std::uint32_t index;

            if (!m_freeList.empty())
            {
                index = m_freeList.back();
                m_freeList.pop_back();
                m_slots[index].alive = true;
            }
            else
            {
                index = static_cast<std::uint32_t>(m_slots.size());
                m_slots.push_back({ .generation = 0, .alive = true });
            }

            const std::uint64_t id = (std::uint64_t(m_slots[index].generation) << 32) | index;
            return Entity { id };
        }

        /**
         * @brief Creates a new entity and immediately attaches the given components.
         *
         * Equivalent to calling @ref Spawn() followed by @ref Add for each component,
         * but more convenient at the call site.
         *
         * @tparam COMPONENTS Component types to attach. Deduced from the arguments.
         * @param  components Component values to move into the entity's storage.
         * @return A valid, alive entity handle with all provided components attached.
         */
        template<typename... COMPONENTS>
        [[nodiscard]] Entity Spawn(COMPONENTS&&... components)
        {
            Entity e = Spawn();
            (Add<COMPONENTS>(e, std::forward<COMPONENTS>(components)), ...);
            return e;
        }

        /**
         * @brief Destroys an entity and removes all of its components.
         *
         * The entity handle becomes stale after this call. Any copies of the
         * handle will fail @ref IsAlive checks.
         */
        void Kill(Entity e)
        {
            if (!IsAlive(e))
                return;

            const std::uint32_t index = static_cast<std::uint32_t>(e.id & 0xFFFFFFFF);

            for (auto& [key, set] : m_sets)
                set->Remove(e);

            m_slots[index].generation++;
            m_slots[index].alive = false;
            m_freeList.push_back(index);
        }

        /**
         * @brief Returns true if @p e is a valid, live entity.
         *
         * Returns false for NullEntity, killed entities, or stale handles from
         * before a Kill+Spawn cycle on the same slot.
         */
        [[nodiscard]] bool IsAlive(Entity e) const
        {
            if (!e)
                return false;

            const std::uint32_t index = static_cast<std::uint32_t>(e.id & 0xFFFFFFFF);
            const std::uint32_t gen   = static_cast<std::uint32_t>(e.id >> 32);

            return index < m_slots.size()
                && m_slots[index].alive
                && m_slots[index].generation == gen;
        }

        /**
         * @brief Attaches a component of type @p T to @p e.
         *
         * If @p e already has a component of type @p T, it is replaced.
         *
         * @return A reference to the stored item.
         */
        template<typename T>
        T& Add(Entity e, T component)
        {
            assert(IsAlive(e) && "Cannot add component to a dead entity.");
            return m_GetOrCreate<T>().Emplace(e, std::move(component));
        }

        /**
         * @brief Removes the component of type @p T from @p e, if present.
         */
        template<typename T>
        void Remove(Entity e)
        {
            if (auto* set = m_Find<T>())
                set->Remove(e);
        }

        /**
         * @brief Returns true if @p e has a component of type @p T.
         */
        template<typename T>
        [[nodiscard]] bool HasComponent(Entity e) const
        {
            auto key = std::type_index(typeid(T));
            auto it = m_sets.find(key);
            return it != m_sets.end() && it->second->Contains(e);
        }

        /**
         * @brief Returns true if @p e has ALL of the listed component types.
         */
        template<typename T, typename... Rest>
        [[nodiscard]] bool HasComponents(Entity e) const
        {
            return Has<T>(e) && (Has<Rest>(e) && ...);
        }

        /**
         * @brief Returns true if @p e has AT LEAST ONE of the listed component types.
         */
        template<typename T, typename... Rest>
        [[nodiscard]] bool HasAnyComponent(Entity e) const
        {
            return Has<T>(e) || (Has<Rest>(e) || ...);
        }

        /**
         * @brief Returns a pointer to the component of type @p T on @p e, or nullptr.
         */
        template<typename T>
        [[nodiscard]] T* GetComponent(Entity e)
        {
            if (auto* set = m_Find<T>())
                return set->Get(e);
            return nullptr;
        }

        template<typename T>
        [[nodiscard]] const T* GetComponent(Entity e) const
        {
            auto key = std::type_index(typeid(T));
            auto it = m_sets.find(key);
            if (it == m_sets.end())
                return nullptr;
            return static_cast<const detail::SparseSet<T>*>(it->second.get())->Get(e);
        }

        /**
         * @brief Returns a reference to the item of type @p T on @p e.
         * @pre @p e must have item @p T. Asserts in debug.
         */
        template<typename T>
        [[nodiscard]] T& RequireComponent(Entity e)
        {
            T* ptr = GetComponent<T>(e);
            assert(ptr && "Entity does not have required component.");
            return *ptr;
        }

        /**
         * @brief Returns a @ref QueryView over entities that possess all of @p COMPONENTS.
         *
         * Chain @ref QueryView::Where to add predicates, then call @ref QueryView::Each
         * to iterate matching entities.
         *
         * The query does not snapshot - item data is accessed live during iteration.
         * Do not add or remove components while iterating.
         *
         * Example:
         * @code
         *   // All entities closer than 10 units from 'origin' that have both Transform and Health.
         *   scene.Query<Transform, Health>()
         *        .Where([&](Entity, const Transform& t, const Health&) {
         *            return glm::length(t.position) < 10.0f;
         *        })
         *        .Each([](Entity, Transform& t, Health& h) { ... });
         * @endcode
         */
        template<typename... COMPONENTS>
        [[nodiscard]] QueryView<COMPONENTS...> Query()
        {
            return QueryView<COMPONENTS...>(this, &m_GetOrCreate<COMPONENTS>()...);
        }

        /** @brief Returns the number of currently alive entities. */
        [[nodiscard]] std::size_t NumEntities() const
        {
            std::size_t count = 0;
            for (auto& slot : m_slots)
                if (slot.alive) ++count;
            return count;
        }

        /** @brief Returns the number of entities that have component @p T. */
        template<typename T>
        [[nodiscard]] std::size_t Count() const
        {
            auto key = std::type_index(typeid(T));
            auto it = m_sets.find(key);
            if (it == m_sets.end())
                return 0;
            return static_cast<const detail::SparseSet<T>*>(it->second.get())->Size();
        }

        /**
         * @brief Destroys all entities and clears all component data.
         */
        void Clear()
        {
            m_sets.clear();
            m_slots.clear();
            m_freeList.clear();
        }
    };
}

#endif /* TS_ECS_H */