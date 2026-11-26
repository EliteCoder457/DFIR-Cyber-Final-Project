elif page==pages[3]:

    hero(
        'ENGINE 02 / URL',
        'URL intelligence',
        'Decompose URL identity and navigation signals and quantify lexical anomalies.'
    )

    target=st.text_input(
        'Target URL',
        placeholder='https://example.org/account/verify',
        key='target_url'
    )

    if st.button('▶ Execute URL inspection',type='primary'):

        try:

            with st.spinner('Parsing URL and evaluating indicators...'):
                result=analyze_url(target,online=False)

            st.session_state.last_url_analysis=result
            store('url',result)
            st.success('URL inspection complete.')

        except Exception as e:
            st.error(f'URL inspection failed: {e}')

    if st.session_state.last_url_analysis:
        display_url(st.session_state.last_url_analysis)
