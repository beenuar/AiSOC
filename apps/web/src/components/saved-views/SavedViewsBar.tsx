'use client';

/**
 * Workstream F3 — saved-views toolbar.
 *
 * A generic, page-agnostic bar that hangs above any list view. Reads the
 * current filter shape via the parent's ``filters`` prop, persists it to the
 * backend as a named preset, and emits the loaded preset's filters back via
 * ``onApply`` when the analyst clicks on one.
 *
 * Why generic? The ``filters`` blob the backend stores is opaque
 * ``Record<string, unknown>``. Each list page (alerts, cases, investigations,
 * playbooks) owns its own filter shape — Alerts uses ``AlertFilters``, Cases
 * uses ``CaseFilters``, etc. Forcing one shared interface across all of them
 * would be a coordination tax for zero benefit. So the bar accepts a generic
 * ``T`` and the caller casts on the way in/out.
 *
 * What it does NOT do:
 *   - Save column overrides. Column ordering/visibility lives at the page
 *     level today; the backend already accepts a ``columns`` field, so a
 *     follow-up can layer this in without re-shaping the API.
 *   - Sync filters into the URL. That's a separate feature (deep-linkable
 *     views) and would deserve its own controller.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import useSWR from 'swr';
import toast from 'react-hot-toast';
import { clsx } from 'clsx';
import {
  savedViewsApi,
  type SavedView,
  type SavedViewType,
  ApiError,
} from '@/lib/api';

// Why ``object`` instead of ``Record<string, unknown>``? TypeScript does not
// infer an index signature for declared interfaces (e.g. ``AlertFilters``), so
// constraining the generic to ``Record<string, unknown>`` fails at every call
// site that passes a typed filter shape. ``object`` is permissive enough to
// keep the API ergonomic, and the cast on the way out (``as TFilters``) keeps
// the contract honest at the boundary.
interface SavedViewsBarProps<TFilters extends object> {
  /** Which list page we're attached to. Drives the backend allowlist. */
  viewType: SavedViewType;
  /**
   * The page's *current* filters. We snapshot this when the analyst clicks
   * "Save current view…" so callers don't need to pass anything extra.
   */
  filters: TFilters;
  /**
   * Apply a preset's filters to the page. The page is responsible for
   * resetting pagination, etc. — this hook just hands the blob over.
   */
  onApply: (filters: TFilters) => void;
  /**
   * Optional: notify the page when a default-loaded view fires on first
   * mount, so it can avoid double-applying or fire analytics.
   */
  onDefaultLoaded?: (view: SavedView) => void;
  /** Hide the "Save current view" affordance, e.g. in read-only demos. */
  readOnly?: boolean;
}

export function SavedViewsBar<TFilters extends object>({
  viewType,
  filters,
  onApply,
  onDefaultLoaded,
  readOnly = false,
}: SavedViewsBarProps<TFilters>) {
  // Each page key is unique so multiple bars on the same screen wouldn't
  // collide — defensive, today the bar is singleton-per-page.
  const cacheKey = ['saved-views', viewType] as const;
  const {
    data: views = [],
    error,
    isLoading,
    mutate,
  } = useSWR(cacheKey, () => savedViewsApi.list(viewType), {
    // Saved views change rarely; aggressive revalidation just adds noise.
    revalidateOnFocus: false,
  });

  // Which preset is lit up. Identified by id rather than by deep-comparing
  // filters, which would be brittle once columns join the picture.
  //
  // Derived, not stored: until the analyst picks something the highlight
  // follows the default view, so loading it needs no state write at all. The
  // wrapper object distinguishes "has not picked yet" (`null`) from "picked
  // nothing", which is the state a delete leaves behind — collapsing the two
  // would re-light the default chip the moment its row was removed.
  const [picked, setPicked] = useState<{ id: string | null } | null>(null);
  const defaultViewId = isLoading ? null : (views.find((v) => v.is_default)?.id ?? null);
  const activeViewId = picked ? picked.id : defaultViewId;

  const [openMenuId, setOpenMenuId] = useState<string | null>(null);
  const [isSaveDialogOpen, setSaveDialogOpen] = useState(false);
  const [renamingViewId, setRenamingViewId] = useState<string | null>(null);

  // Keep the latest callbacks reachable from the effect below without putting
  // them in its dependency list. Callers pass inline arrows, so a new identity
  // arrives on every parent render; depending on them would re-run the effect
  // constantly and reading a stale one would apply the wrong page's filters.
  const onApplyRef = useRef(onApply);
  const onDefaultLoadedRef = useRef(onDefaultLoaded);
  useEffect(() => {
    onApplyRef.current = onApply;
    onDefaultLoadedRef.current = onDefaultLoaded;
  });

  // Hand the default view's filters to the page, once per mount.
  //
  // This ran in the render body until it was found to call `onApply` — which
  // for every real caller is a setState on the page component — while this
  // component was still rendering. React refuses that ("Cannot update a
  // component while rendering a different component") and makes no promise
  // about processing the parent's update, so the filters an analyst expected
  // restored were not reliably applied. The ref-flag the old comment described
  // did not exist; it was `useState`, with no effect anywhere.
  //
  // Notifying the page is the only thing left here, because the chip highlight
  // is derived above. A ref for the flag so it cannot itself trigger a render,
  // and so later SWR revalidations do not re-clobber filters the analyst has
  // since changed.
  const defaultAppliedRef = useRef(false);
  useEffect(() => {
    if (defaultAppliedRef.current || isLoading || views.length === 0) return;
    defaultAppliedRef.current = true;

    const def = views.find((v) => v.is_default);
    if (!def) return;

    onApplyRef.current(def.filters as TFilters);
    onDefaultLoadedRef.current?.(def);
  }, [views, isLoading]);

  const apply = useCallback(
    (view: SavedView) => {
      setPicked({ id: view.id });
      setOpenMenuId(null);
      onApply(view.filters as TFilters);
    },
    [onApply],
  );

  const handleCreate = useCallback(
    async (name: string, makeDefault: boolean) => {
      try {
        const created = await savedViewsApi.create({
          view_type: viewType,
          name,
          filters: filters as Record<string, unknown>,
          is_default: makeDefault,
        });
        await mutate();
        setPicked({ id: created.id });
        toast.success(`Saved view "${created.name}"`);
        setSaveDialogOpen(false);
      } catch (err) {
        const message =
          err instanceof ApiError && err.status === 409
            ? `A view named "${name}" already exists`
            : err instanceof Error
              ? err.message
              : 'Failed to save view';
        toast.error(message);
      }
    },
    [filters, mutate, viewType],
  );

  const handleRename = useCallback(
    async (id: string, name: string) => {
      try {
        await savedViewsApi.update(id, { name });
        await mutate();
        toast.success('Renamed');
        setRenamingViewId(null);
      } catch (err) {
        const message =
          err instanceof ApiError && err.status === 409
            ? `A view named "${name}" already exists`
            : err instanceof Error
              ? err.message
              : 'Rename failed';
        toast.error(message);
      }
    },
    [mutate],
  );

  const handleSetDefault = useCallback(
    async (view: SavedView) => {
      const next = !view.is_default;
      try {
        await savedViewsApi.update(view.id, { is_default: next });
        await mutate();
        toast.success(next ? 'Set as default' : 'Default cleared');
        setOpenMenuId(null);
      } catch (err) {
        toast.error(err instanceof Error ? err.message : 'Update failed');
      }
    },
    [mutate],
  );

  const handleOverwrite = useCallback(
    async (view: SavedView) => {
      try {
        await savedViewsApi.update(view.id, {
          filters: filters as Record<string, unknown>,
        });
        await mutate();
        setPicked({ id: view.id });
        toast.success(`Updated "${view.name}"`);
        setOpenMenuId(null);
      } catch (err) {
        toast.error(err instanceof Error ? err.message : 'Update failed');
      }
    },
    [filters, mutate],
  );

  const handleDelete = useCallback(
    async (view: SavedView) => {
      // No confirm() prompt — analysts have a 'recently deleted' fallback
      // already by re-saving the current filters. Keeps the workflow snappy.
      try {
        await savedViewsApi.delete(view.id);
        await mutate();
        if (activeViewId === view.id) setPicked({ id: null });
        setOpenMenuId(null);
        toast.success(`Deleted "${view.name}"`);
      } catch (err) {
        toast.error(err instanceof Error ? err.message : 'Delete failed');
      }
    },
    [activeViewId, mutate],
  );

  return (
    <div
      className="flex items-center gap-2 flex-wrap py-2 px-3 bg-gray-900/40 border border-gray-800/60 rounded-xl"
      data-testid="saved-views-bar"
    >
      <span className="text-xs text-gray-500 mr-1 shrink-0">Saved views</span>

      {error && (
        <span className="text-xs text-red-400">Failed to load saved views</span>
      )}

      {!error && views.length === 0 && !isLoading && (
        <span className="text-xs text-gray-600 italic">
          None yet — save your current filters to come back to them later.
        </span>
      )}

      {views.map((view) => (
        <div key={view.id} className="relative inline-flex">
          {renamingViewId === view.id ? (
            <RenameInput
              initial={view.name}
              onSubmit={(name) => handleRename(view.id, name)}
              onCancel={() => setRenamingViewId(null)}
            />
          ) : (
            <button
              type="button"
              onClick={() => apply(view)}
              className={clsx(
                'inline-flex items-center gap-1 text-xs px-2.5 py-1 rounded-l-lg transition-colors border-l border-y',
                activeViewId === view.id
                  ? 'bg-blue-600 text-white border-blue-600'
                  : 'text-gray-300 hover:bg-gray-800/60 border-gray-800/60',
              )}
              title={
                view.is_default
                  ? `${view.name} (default)`
                  : `Apply ${view.name}`
              }
              data-testid={`saved-view-chip-${view.id}`}
            >
              {view.is_default && (
                <span aria-label="default" className="text-yellow-400">★</span>
              )}
              <span className="truncate max-w-[12rem]">{view.name}</span>
            </button>
          )}
          {renamingViewId !== view.id && !readOnly && (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                setOpenMenuId(openMenuId === view.id ? null : view.id);
              }}
              className={clsx(
                'inline-flex items-center text-xs px-1.5 py-1 rounded-r-lg transition-colors border-r border-y',
                activeViewId === view.id
                  ? 'bg-blue-700 text-white border-blue-600'
                  : 'text-gray-400 hover:bg-gray-800/60 border-gray-800/60',
              )}
              aria-label={`Actions for ${view.name}`}
              aria-haspopup="menu"
              aria-expanded={openMenuId === view.id}
              data-testid={`saved-view-menu-${view.id}`}
            >
              ⋯
            </button>
          )}

          {openMenuId === view.id && (
            <div
              role="menu"
              className="absolute z-20 top-full left-0 mt-1 w-48 bg-gray-900 border border-gray-800 rounded-lg shadow-xl py-1"
              onClick={(e) => e.stopPropagation()}
            >
              <MenuItem onClick={() => handleSetDefault(view)}>
                {view.is_default ? 'Clear default' : 'Set as default'}
              </MenuItem>
              <MenuItem
                onClick={() => {
                  setRenamingViewId(view.id);
                  setOpenMenuId(null);
                }}
              >
                Rename
              </MenuItem>
              <MenuItem onClick={() => handleOverwrite(view)}>
                Update with current filters
              </MenuItem>
              <MenuItem danger onClick={() => handleDelete(view)}>
                Delete
              </MenuItem>
            </div>
          )}
        </div>
      ))}

      {!readOnly && !isSaveDialogOpen && (
        <button
          type="button"
          onClick={() => setSaveDialogOpen(true)}
          className="text-xs px-2.5 py-1 rounded-lg border border-dashed border-gray-700 text-gray-400 hover:text-gray-200 hover:border-gray-500 transition-colors"
          data-testid="save-current-view-btn"
        >
          + Save current view
        </button>
      )}

      {isSaveDialogOpen && (
        <SaveViewDialog
          onSubmit={handleCreate}
          onCancel={() => setSaveDialogOpen(false)}
        />
      )}
    </div>
  );
}

function MenuItem({
  children,
  onClick,
  danger = false,
}: {
  children: React.ReactNode;
  onClick: () => void;
  danger?: boolean;
}) {
  return (
    <button
      role="menuitem"
      type="button"
      onClick={onClick}
      className={clsx(
        'w-full text-left text-xs px-3 py-1.5 transition-colors',
        danger
          ? 'text-red-400 hover:bg-red-500/10'
          : 'text-gray-300 hover:bg-gray-800',
      )}
    >
      {children}
    </button>
  );
}

function RenameInput({
  initial,
  onSubmit,
  onCancel,
}: {
  initial: string;
  onSubmit: (name: string) => void;
  onCancel: () => void;
}) {
  const [value, setValue] = useState(initial);
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        const trimmed = value.trim();
        if (trimmed) onSubmit(trimmed);
      }}
      className="inline-flex items-center"
    >
      <input
        autoFocus
        type="text"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Escape') onCancel();
        }}
        maxLength={120}
        className="text-xs px-2 py-1 rounded bg-gray-900 border border-blue-500/50 text-gray-200 focus:outline-none focus:border-blue-400 w-40"
        aria-label="Rename saved view"
      />
    </form>
  );
}

function SaveViewDialog({
  onSubmit,
  onCancel,
}: {
  onSubmit: (name: string, isDefault: boolean) => void;
  onCancel: () => void;
}) {
  const [name, setName] = useState('');
  const [isDefault, setIsDefault] = useState(false);

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        const trimmed = name.trim();
        if (trimmed) onSubmit(trimmed, isDefault);
      }}
      className="inline-flex items-center gap-2"
      data-testid="save-view-dialog"
    >
      <input
        autoFocus
        type="text"
        value={name}
        onChange={(e) => setName(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Escape') onCancel();
        }}
        placeholder="View name"
        maxLength={120}
        className="text-xs px-2 py-1 rounded bg-gray-900 border border-blue-500/50 text-gray-200 focus:outline-none focus:border-blue-400 w-44"
        aria-label="New saved view name"
      />
      <label className="inline-flex items-center gap-1 text-xs text-gray-400 select-none">
        <input
          type="checkbox"
          checked={isDefault}
          onChange={(e) => setIsDefault(e.target.checked)}
          className="accent-blue-500"
        />
        Default
      </label>
      <button
        type="submit"
        disabled={!name.trim()}
        className="text-xs px-2.5 py-1 rounded-lg bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-40 disabled:cursor-not-allowed"
      >
        Save
      </button>
      <button
        type="button"
        onClick={onCancel}
        className="text-xs px-2 py-1 rounded-lg text-gray-400 hover:text-gray-200"
      >
        Cancel
      </button>
    </form>
  );
}
