"""
Graph visualization tool for consistency models.
Generates execution graph images from JSON files.
"""

import json
import os
import sys

import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.patches import FancyArrowPatch


class JSONEventGraphParser:
    """Parser for JSON files containing event graph information."""

    def __init__(self, graph_file):
        """
        Initialize parser with a JSON graph file.

        Args:
            graph_file: Path to JSON file containing events and relations
        """
        self.graph_file = graph_file
        self.events = {}      # instruction_id -> {id, tid, kind, loc, mode}
        self.locations = set()
        self.edges = {
            "PO": [],  # Program order
            "MO": [],  # Modification order
            "RF": [],  # Read-from
            "SW": [],  # Synchronizes-with
        }

    def _eid(self, raw_id):
        """Convert numeric instruction_id to internal string id."""
        return f"i{raw_id}"

    def parse(self):
        """Parse the JSON file for locations, events, and relations."""
        with open(self.graph_file, "r") as f:
            data = json.load(f)

        # --------------------------------------------------
        # Parse events (nodes)
        # --------------------------------------------------
        for node in data.get("nodes", []):
            instruction_id = self._eid(node["instruction_id"])
            tid = node["thread_id"]
            kind = node["kind"]
            loc = node["loc"]
            mode = node.get("access_mode", "RLX").upper()

            self.events[instruction_id] = {
                "id": instruction_id,
                "tid": tid,
                "kind": kind,
                "loc": loc,
                "mode": mode,
            }

            self.locations.add(loc)

        # --------------------------------------------------
        # Parse MO (modification order)
        # --------------------------------------------------
        # Each list is already ordered per location
        for mo in data.get("mo_per_location", []):
            event_list = mo.get("list", [])
            for i in range(len(event_list) - 1):
                e1 = self._eid(event_list[i][1])
                e2 = self._eid(event_list[i + 1][1])
                self.edges["MO"].append((e1, e2))

        # --------------------------------------------------
        # Parse PO (program order)
        # --------------------------------------------------
        # Use po_edges if present (explicit edges)
        for po in data.get("po_edges", []):
            src = self._eid(po["from"][1])
            for dst in po.get("to", []):
                dst_id = self._eid(dst[1])
                self.edges["PO"].append((src, dst_id))

        # Fallback: derive PO from po_per_thread lists
        if not self.edges["PO"]:
            for thread in data.get("po_per_thread", []):
                lst = thread.get("list", [])
                for i in range(len(lst) - 1):
                    e1 = self._eid(lst[i][1])
                    e2 = self._eid(lst[i + 1][1])
                    self.edges["PO"].append((e1, e2))

        # --------------------------------------------------
        # Parse RF (read-from)
        # --------------------------------------------------
        for rf in data.get("rf_edges", []):
            src = self._eid(rf["from"][1])
            for dst in rf.get("to", []):
                dst_id = self._eid(dst[1])
                self.edges["RF"].append((src, dst_id))

        # --------------------------------------------------
        # Parse SW (synchronizes-with)
        # --------------------------------------------------
        for sw in data.get("sw_edges", []):
            src = self._eid(sw["from"][1])
            for dst in sw.get("to", []):
                dst_id = self._eid(dst[1])
                self.edges["SW"].append((src, dst_id))

    def get_event_label(self, instruction_id):
        """Generate label for an event (with event ID and details)."""
        if instruction_id not in self.events:
            return instruction_id

        event = self.events[instruction_id]
        kind = event["kind"]
        loc = event["loc"]
        tid = event["tid"]
        mode = event.get("mode", "RLX")

        return f"{kind}({loc}) [{mode}]\n{instruction_id}\nT{tid}"


class EventGraphVisualizer:
    """Visualizer for event graphs."""

    def __init__(self, parser):
        """
        Initialize visualizer with parsed graph data.

        Args:
            parser: JSONEventGraphParser instance
        """
        self.parser = parser
        self.graph = nx.MultiDiGraph()
        self.pos = {}
        self._build_graph()

    def _build_graph(self):
        """Build networkx graph from parsed data."""
        # Add nodes
        for instruction_id in self.parser.events:
            label = self.parser.get_event_label(instruction_id)
            self.graph.add_node(instruction_id, label=label)

        # Add edges from all relations
        for edge_type, edges in self.parser.edges.items():
            for source, target in edges:
                self.graph.add_edge(source, target, relation=edge_type)

    def _compute_layout(self):
        """Compute node positions: main thread (0) vertical, then parallel threads side-by-side."""
        self.pos = {}

        # Group events by thread
        tid_to_events = {}
        for instruction_id, event in self.parser.events.items():
            tid = event['tid']
            if tid not in tid_to_events:
                tid_to_events[tid] = []
            tid_to_events[tid].append(instruction_id)

        sorted_threads = sorted(tid_to_events.keys())

        # Build PO ordering for each thread
        thread_po_order = {}
        for tid in sorted_threads:
            events_in_thread = tid_to_events[tid]

            # Build PO subgraph for this thread
            po_subgraph = nx.DiGraph()
            po_subgraph.add_nodes_from(events_in_thread)

            for src, tgt in self.parser.edges["PO"]:
                if src in events_in_thread and tgt in events_in_thread:
                    po_subgraph.add_edge(src, tgt)

            # Get topological ordering
            try:
                po_ordered = list(nx.topological_sort(po_subgraph))
            except nx.NetworkXError:
                po_ordered = events_in_thread

            thread_po_order[tid] = po_ordered

        # Check if single thread or multiple threads
        is_single_thread = len(sorted_threads) == 1

        if is_single_thread:
            # Single thread: straight vertical line
            po_ordered = thread_po_order[0]
            for idx, instruction_id in enumerate(po_ordered):
                self.pos[instruction_id] = (0, -idx * 1.5)
        else:
            # Multiple threads: thread 0 vertical, then parallel threads
            # Position thread 0 (main thread) vertically
            main_thread_po = thread_po_order[0]
            event_spacing = 1.5

            for idx, instruction_id in enumerate(main_thread_po):
                self.pos[instruction_id] = (0, -idx * event_spacing)

            # Starting y position for parallel threads (after main thread ends)
            parallel_start_y = -(len(main_thread_po) - 1) * event_spacing - 2

            # Position parallel threads (tid >= 1) side-by-side
            parallel_threads = [t for t in sorted_threads if t > 0]
            num_parallel = len(parallel_threads)

            if num_parallel > 0:
                # Calculate horizontal spacing for parallel threads
                thread_spacing_x = 4

                for thread_idx, tid in enumerate(parallel_threads):
                    # X position for this thread
                    x = (thread_idx - num_parallel / 2 + 0.5) * thread_spacing_x

                    # temporary fix -- to make the first graph legible
                    if tid > 0:
                        x -= 0.5

                    # Y positions for events in this thread (all at same starting level)
                    po_ordered = thread_po_order[tid]
                    for instruction_idx, instruction_id in enumerate(po_ordered):
                        y = parallel_start_y - instruction_idx * event_spacing
                        self.pos[instruction_id] = (x, y)

    def visualize(self, output_file="graph.png", figsize=(14, 10)):
        """
        Generate and save visualization.

        Args:
            output_file: Path to save the output image
            figsize: Figure size (width, height)
        """
        self._compute_layout()

        fig, ax = plt.subplots(figsize=figsize)

        # Draw nodes
        node_labels = {instruction_id: self.parser.get_event_label(instruction_id)
                       for instruction_id in self.graph.nodes()}

        nx.draw_networkx_nodes(
            self.graph, self.pos, node_color="lightblue", node_size=2500, ax=ax
        )
        nx.draw_networkx_labels(
            self.graph, self.pos, labels=node_labels, font_size=9, ax=ax
        )

        # Draw edges with different styles based on relation type
        edge_styles = {
            "PO": {
                "color": "black",
                "style": "-",
                "width": 2.5,
                "head_width": 0.4,
                "head_length": 0.3,
            },
            "MO": {
                "color": "orange",
                "style": "--",
                "width": 2.5,
                "head_width": 0.4,
                "head_length": 0.3,
            },
            "RF": {
                "color": "green",
                "style": "--",
                "width": 2.5,
                "head_width": 0.4,
                "head_length": 0.3,
            },
            "SW": {
                "color": "purple",
                "style": "--",
                "width": 2.5,
                "head_width": 0.4,
                "head_length": 0.3,
            },
        }

        # Group edges by (src, tgt) to spread multiple relations between same nodes
        edge_groups = {}
        for src, tgt, key, data in self.graph.edges(data=True, keys=True):
            pair = (src, tgt)
            edge_groups.setdefault(pair, []).append(data)

        def arc_offset(index: int) -> float:
            """Return arc radius offset so parallel edges don't overlap."""
            sequence = [0.0, 0.2, -0.2, 0.35, -0.35, 0.5, -0.5]
            return (
                sequence[index]
                if index < len(sequence)
                else 0.6 * ((index // 2) + 1) * (1 if index % 2 == 0 else -1)
            )

        for (src, tgt), datas in edge_groups.items():
            for idx, data in enumerate(datas):
                relation_type = data.get("relation", "PO")
                style = edge_styles.get(relation_type, edge_styles["PO"])

                # Get positions
                x1, y1 = self.pos[src]
                x2, y2 = self.pos[tgt]

                # Calculate direction and length
                dx = x2 - x1
                dy = y2 - y1
                length = (dx**2 + dy**2) ** 0.5

                # Normalize direction
                if length > 0:
                    dx_norm = dx / length
                    dy_norm = dy / length
                else:
                    dx_norm, dy_norm = 0, 0

                # Shorten start and end points to account for node size
                node_radius = 0.25
                start_x = x1 + dx_norm * node_radius
                start_y = y1 + dy_norm * node_radius
                end_x = x2 - dx_norm * node_radius
                end_y = y2 - dy_norm * node_radius

                # Edge-specific curvature to avoid overlap
                rad = arc_offset(idx)

                # Draw line with arrow
                arrow = FancyArrowPatch(
                    (start_x, start_y),
                    (end_x, end_y),
                    arrowstyle="-|>",
                    color=style["color"],
                    linestyle=style["style"],
                    linewidth=style["width"],
                    mutation_scale=35,
                    zorder=0,
                    connectionstyle=f"arc3,rad={rad}",
                )
                ax.add_patch(arrow)

        # Create legend for edge types
        from matplotlib.lines import Line2D

        legend_elements = [
            Line2D(
                [0],
                [0],
                color="black",
                linewidth=2.5,
                label="PO (Program Order)",
                marker=">",
            ),
            Line2D(
                [0],
                [0],
                color="orange",
                linewidth=2.5,
                linestyle="--",
                label="MO (Modification Order)",
                marker=">",
            ),
            Line2D(
                [0],
                [0],
                color="green",
                linewidth=2.5,
                linestyle="--",
                label="RF (Read-From)",
                marker=">",
            ),
            Line2D(
                [0],
                [0],
                color="purple",
                linewidth=2.5,
                linestyle="--",
                label="SW (Synchronizes-With)",
                marker=">",
            ),
        ]
        ax.legend(handles=legend_elements, loc="upper left", fontsize=10)

        # Add thread information as title
        threads = sorted(set(event["tid"] for event in self.parser.events.values()))
        if len(threads) > 1:
            thread_info = "Thread 0 (Parent) | Threads " + ", ".join(
                str(t) for t in threads[1:]
            )
        else:
            thread_info = "Single Thread"
        ax.set_title(thread_info, fontsize=12, fontweight="bold")

        ax.set_aspect("equal")
        ax.axis("off")
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches="tight")
        print(f"Graph saved to {output_file}")
        plt.close()


def generate_graph_visualization(json_file_path):
    """
    Generate graph visualization from JSON file.

    Args:
        json_file_path: Path to JSON file containing event graph
    """
    if not os.path.exists(json_file_path):
        print(f"Error: File not found: {json_file_path}")
        return

    try:
        # Parse JSON file
        parser = JSONEventGraphParser(json_file_path)
        parser.parse()

        # Generate output filename
        base_dir = os.path.dirname(json_file_path)
        file_name = os.path.basename(json_file_path)
        base_name = os.path.splitext(file_name)[0]

        # Create graphs subdirectory if needed
        graphs_dir = os.path.join(base_dir, "graphs")
        os.makedirs(graphs_dir, exist_ok=True)

        output_file = os.path.join(graphs_dir, f"{base_name}_graph.png")

        # Generate visualization
        visualizer = EventGraphVisualizer(parser)
        visualizer.visualize(output_file=output_file)

    except FileNotFoundError as e:
        print(f"Error: {e}")
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON file: {e}")
    except Exception as e:
        print(f"Error generating visualization: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python visualize.py <json_file_path>")
        print(
            "Example: python visualize.py testcases/msg_passing/output/default/queue/id:000002.json"
        )
        sys.exit(1)

    json_file_path = sys.argv[1]
    generate_graph_visualization(json_file_path)
