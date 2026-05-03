import React from 'react';
import ComponentCreator from '@docusaurus/ComponentCreator';

export default [
  {
    path: '/aisoc/blog',
    component: ComponentCreator('/aisoc/blog', '846'),
    exact: true
  },
  {
    path: '/aisoc/docs',
    component: ComponentCreator('/aisoc/docs', '221'),
    routes: [
      {
        path: '/aisoc/docs',
        component: ComponentCreator('/aisoc/docs', '9e5'),
        routes: [
          {
            path: '/aisoc/docs',
            component: ComponentCreator('/aisoc/docs', 'f34'),
            routes: [
              {
                path: '/aisoc/docs/api/graphql',
                component: ComponentCreator('/aisoc/docs/api/graphql', 'd5d'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/aisoc/docs/api/rest',
                component: ComponentCreator('/aisoc/docs/api/rest', '007'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/aisoc/docs/api/websocket',
                component: ComponentCreator('/aisoc/docs/api/websocket', 'c72'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/aisoc/docs/architecture',
                component: ComponentCreator('/aisoc/docs/architecture', 'a6a'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/aisoc/docs/concepts/cases',
                component: ComponentCreator('/aisoc/docs/concepts/cases', '792'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/aisoc/docs/concepts/detections',
                component: ComponentCreator('/aisoc/docs/concepts/detections', 'e4f'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/aisoc/docs/concepts/playbooks',
                component: ComponentCreator('/aisoc/docs/concepts/playbooks', '550'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/aisoc/docs/contributing/dev-setup',
                component: ComponentCreator('/aisoc/docs/contributing/dev-setup', '97d'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/aisoc/docs/contributing/guidelines',
                component: ComponentCreator('/aisoc/docs/contributing/guidelines', '4c1'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/aisoc/docs/deployment/docker',
                component: ComponentCreator('/aisoc/docs/deployment/docker', 'a14'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/aisoc/docs/deployment/env-vars',
                component: ComponentCreator('/aisoc/docs/deployment/env-vars', '5bd'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/aisoc/docs/deployment/kubernetes',
                component: ComponentCreator('/aisoc/docs/deployment/kubernetes', '131'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/aisoc/docs/intro',
                component: ComponentCreator('/aisoc/docs/intro', '1b8'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/aisoc/docs/plugins/go-sdk',
                component: ComponentCreator('/aisoc/docs/plugins/go-sdk', '968'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/aisoc/docs/plugins/overview',
                component: ComponentCreator('/aisoc/docs/plugins/overview', '7e0'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/aisoc/docs/plugins/publishing',
                component: ComponentCreator('/aisoc/docs/plugins/publishing', 'ed0'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/aisoc/docs/plugins/python-sdk',
                component: ComponentCreator('/aisoc/docs/plugins/python-sdk', 'c2d'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/aisoc/docs/quickstart',
                component: ComponentCreator('/aisoc/docs/quickstart', 'dbd'),
                exact: true,
                sidebar: "docsSidebar"
              }
            ]
          }
        ]
      }
    ]
  },
  {
    path: '/aisoc/',
    component: ComponentCreator('/aisoc/', '0a4'),
    exact: true
  },
  {
    path: '*',
    component: ComponentCreator('*'),
  },
];
