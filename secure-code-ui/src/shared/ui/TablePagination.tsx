// secure-code-ui/src/shared/ui/TablePagination.tsx
//
// Paging for long tables, in one place.
//
// Every table in the app had its own pager with slightly different labels and a different idea of
// what happens at the edges. This is the one behaviour: a page count, a row count, and buttons
// that disable rather than disappear at the ends.

export function TablePagination({
  page,
  pageSize,
  total,
  onPageChange,
  onPageSizeChange,
  sizes = [20, 50, 100],
}: {
  page: number;
  pageSize: number;
  total: number;
  onPageChange: (page: number) => void;
  onPageSizeChange?: (size: number) => void;
  sizes?: number[];
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(page * pageSize, total);

  return (
    <div className="asset-pager">
      <span className="asset-muted">
        Showing {from}–{to} of {total}
      </span>
      {onPageSizeChange && (
        <label className="asset-muted">
          Rows
          <select
            value={pageSize}
            onChange={(event) => onPageSizeChange(Number(event.target.value))}
          >
            {sizes.map((size) => (
              <option key={size} value={size}>
                {size}
              </option>
            ))}
          </select>
        </label>
      )}
      <div className="asset-pager-buttons">
        <button
          className="sccap-btn sccap-btn-sm"
          disabled={page <= 1}
          onClick={() => onPageChange(page - 1)}
        >
          Previous
        </button>
        <span className="asset-muted">
          Page {page} of {pages}
        </span>
        <button
          className="sccap-btn sccap-btn-sm"
          disabled={page >= pages}
          onClick={() => onPageChange(page + 1)}
        >
          Next
        </button>
      </div>
    </div>
  );
}

export default TablePagination;
