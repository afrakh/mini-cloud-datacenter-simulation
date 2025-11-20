async function loadAndDraw() {
    const res = await fetch('/api/topology');
    const net = await res.json();
    draw(net);
}

function draw(data) {
    const svg = d3.select('#topoSvg');
    svg.selectAll('*').remove();
    const width = svg.node().clientWidth;
    const height = svg.node().clientHeight;

    const color = d3.scaleOrdinal(d3.schemeTableau10);

    // Assign initial positions so nodes don't fly randomly
    data.nodes.forEach((d, i) => {
        d.x = width/2 + Math.random()*100 - 50;
        d.y = height/2 + Math.random()*100 - 50;
    });

    const simulation = d3.forceSimulation(data.nodes)
        .force('link', d3.forceLink(data.links).id(d => d.id).distance(120))
        .force('charge', d3.forceManyBody().strength(-500))
        .force('center', d3.forceCenter(width/2, height/2))
        .force('collision', d3.forceCollide().radius(d => d.type === 'switch' ? 25 : 15)) // prevent overlap
        .alpha(1)  // start strong
        .alphaDecay(0.05); // stabilize faster

    const link = svg.append('g')
        .attr('stroke', '#999')
        .attr('stroke-opacity', 0.6)
        .selectAll('line')
        .data(data.links)
        .join('line')
        .attr('stroke-width', 2);

    const node = svg.append('g')
        .selectAll('g')
        .data(data.nodes)
        .join('g')
        .call(d3.drag()
            .on("start", dragstarted)
            .on("drag", dragged)
            .on("end", dragended));

    node.append('circle')
        .attr('r', d => d.type === 'switch' ? 18 : 12)
        .attr('fill', d => color(d.type));

    node.append('text')
        .attr('x', 14)
        .attr('y', 4)
        .text(d => d.id)
        .attr('font-size', '12px');

    simulation.on('tick', () => {
        link
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);

        node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    // Drag functions
    function dragstarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x; d.fy = d.y;
    }
    function dragged(event, d) {
        d.fx = event.x; d.fy = event.y;
    }
    function dragended(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null; d.fy = null;
    }
}

// Load on start and refresh every 5 seconds
window.addEventListener('load', () => {
    loadAndDraw();
    setInterval(loadAndDraw, 5000);
});

