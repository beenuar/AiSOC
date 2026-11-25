# Dashboard drag handle investigation

Investigation date: 2026-11-24. Base: 9b9d62190d233303e8a43b7a6a4b701e6334d54b.

## Contract and scope

Only the existing Drag to reorder button starts widget reordering. Dashboard
content remains selectable and copyable. Existing saved layouts remain valid.
Clicking the handle without dragging and cancelling a drag must not reorder.

## Evidence and decision

At the base commit, DashboardView.tsx marked the whole DraggableWidget div
draggable and attached its start handler there. The button dispatched a synthetic
dragstart on pointerdown, which changed application state without starting a
native browser drag. The same completion callback was used for drop and dragend,
so cancellation could commit the last hovered target.

| Reference | Match | License | Decision |
| --- | --- | --- | --- |
| Native HTML drag/drop with React event handlers | Existing mechanism; supports a separate draggable source and drop targets | Web platform API; no new dependency | Keep the mechanism and restrict its source to the handle |
| MDN content, drag_operations at 3385bda58637833eedc9b8dc41a2804e653208a7 | Source examples show dataTransfer initialization, conditional dragover, and dragend on both success and cancellation | LICENSE.md: prose CC-BY-SA-2.5, examples CC0 after 2010-08-20 or MIT before that date | Reference API behavior only; no copied implementation |

Read sources:
- https://html.spec.whatwg.org/multipage/dnd.html
- https://github.com/mdn/content/blob/3385bda58637833eedc9b8dc41a2804e653208a7/files/en-us/web/api/html_drag_and_drop_api/drag_operations/index.md
- https://github.com/mdn/content/blob/main/LICENSE.md

Move draggable/start/end to the existing button, remove synthetic pointerdown,
accept drops only while a widget drag is active, and separate commit from cancel.
The actual drop target determines the destination; dragend only clears state.

## Validation plan

Use the real Next app and Chromium mouse/keyboard input. HTTP responses are
explicit synthetic fixtures; these tests do not validate backend/database
behavior. Confirm text selection plus clipboard, handle click, real reorder and
reload persistence, link drag isolation, Escape cancellation, and outside drop.
Record baseline failure, fixed result, and a negative control with the original
component restored in the isolated checkout. Run the relevant web gates and the
root AGENTS pre-push checks. Preserve the existing lockfile and use pnpm 8.15.1.

## Executed regression evidence

The rendered-component suite in DashboardReorder.test.tsx was run with Node
22.23.5, pnpm 8.15.1 and the frozen workspace dependencies. All six cases failed
against the base component, passed with the fix, and failed again when the base
component was temporarily restored as a negative control. The fixed component
was restored afterwards.

Those results cover React event handling and layout persistence. The six native
browser cases in e2e/journeys/dashboard-reorder.spec.ts could not run locally:
Chromium exited before opening a page because the runner denies its Unix socket
creation. No native selection, clipboard, browser screenshot or backend/database
verification is claimed by the component results.
