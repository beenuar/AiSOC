import { CasesView } from '@/components/cases/CasesView';

export const metadata = {
  title: 'Cases',
};

// The /cases page must reflect the current state of the backend on every
// request; static prerendering and CDN caching previously caused stale mock
// data to be served when client-side hydration failed.
export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';

// There is no server-side prefetch here on purpose.
//
// This page used to fetch `/api/v1/cases` during the server render, sending
// `X-Tenant-Id` from a build-time environment variable and no credential at
// all. It returned data because the API resolved an uncredentialed request to
// a demo administrator in a development-class environment, and the tenant it
// read was whichever one the image was built for rather than the one the
// signed-in analyst belongs to.
//
// A server render has no session to borrow: the bearer token lives in the
// browser. So the prefetch cannot be made correct, only removed. `CasesView`
// loads through the credentialed client on mount, which is the only place the
// caller's own identity and tenant are known.
export default function CasesPage() {
  return <CasesView />;
}
