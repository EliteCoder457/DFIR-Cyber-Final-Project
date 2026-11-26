elif page==pages[4]:
    hero(
        'ENGINE 03 / NETWORK',
        'Network intelligence',
        'Authorized local-network visibility: bounded TCP connection checks, port states and service hints.'
    )

    left,right=st.columns([1.2,1])

    with left:
        target=st.text_input(
            'Private or loopback IP address',
            value='127.0.0.1',
            key='network_target',
            help='Examples: 127.0.0.1, 192.168.1.10, 10.0.0.5'
        )

    with right:
        ports=st.text_input(
            'TCP ports (comma-separated; max 24)',
            value='22,80,443,445,3389,8080',
            key='network_ports'
        )

    authorized=st.checkbox(
        'I own or have explicit authorization to assess this host',
        key='network_authorized'
    )

    if st.button('▶ Inspect TCP connectivity',type='primary'):
        try:
            with st.spinner('Checking selected TCP ports with bounded timeouts...'):
                st.session_state.last_network_analysis=analyze_network(
                    target,
                    ports,
                    authorized=authorized
                )

                store(
                    'network',
                    st.session_state.last_network_analysis
                )

            st.success('TCP connectivity check completed.')

        except ValueError as exc:
            st.error(str(exc))

        except OSError as exc:
            st.error(f'Network connectivity check failed: {exc}')

    if st.session_state.last_network_analysis:
        r=st.session_state.last_network_analysis

        label('Network snapshot')

        a,b,c,d=st.columns(4)

        a.metric('Target',r['target'])
        b.metric('TCP open',r['open_count'])
        c.metric('TCP closed',r['closed_count'])
        d.metric('Inconclusive',r['inconclusive_count'])

        tab1,tab2=st.tabs([
            '◈  Port visibility',
            '▣  Scope & evidence'
        ])

        with tab1:
            st.dataframe(
                r['results'],
                hide_index=True,
                use_container_width=True
            )

            if r['open_count']:
                label('Reachable TCP services (port-based hints only)')

                for item in r['results']:
                    if item['status']=='open':
                        st.markdown(
                            f"**TCP {item['port']}** — "
                            f"{html.escape(item['service_hint'])} · "
                            f"connected in {item['elapsed_ms']} ms"
                        )
            else:
                st.caption(
                    'No successful TCP connections observed on the selected ports.'
                )

        with tab2:
            st.json({
                k:v for k,v in r.items()
                if k!='results'
            })

            st.caption(r['note'])

        st.download_button(
            '↓ Export network JSON',
            json.dumps(r,indent=2),
            file_name='network_analysis.json',
            mime='application/json'
        )

        st.caption(
            'Network snapshots can be exported as JSON and are retained '
            'in the active case Evidence Vault.'
        )
